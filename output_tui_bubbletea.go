package main

import (
	"fmt"
	"hash/crc32"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// BubbleTUIOutput is an MTR-like TUI using Bubble Tea
type BubbleTUIOutput struct {
	mu       sync.RWMutex
	program  *tea.Program
	model    *tuiModel
	updateCh chan tuiUpdateMsg
	quitCh   chan struct{}
	doneCh   chan struct{}
}

// tuiUpdateMsg is sent when hop stats are updated
type tuiUpdateMsg struct {
	probeID  uint16
	ttl      uint8
	hopStats HopStats
}

// tickMsg is sent periodically to refresh the display
type tickMsg time.Time

// tuiModel holds the Bubble Tea model state
type tuiModel struct {
	// Data
	probes      map[uint16]*ProbeStats
	mu          sync.RWMutex
	destination string
	protocol    string
	dstPort     uint16
	srcPort     uint16
	startTime   time.Time

	// UI state
	width         int
	height        int
	selectedProbe uint16
	focus         paneFocus
	summaryScroll int
	detailScroll  int
	help          help.Model
	keys          keyMap

	// Channel for receiving updates
	updateCh chan tuiUpdateMsg
	quitCh   chan struct{}
}

// keyMap defines keyboard shortcuts
type keyMap struct {
	Up    key.Binding
	Down  key.Binding
	Left  key.Binding
	Right key.Binding
	Tab   key.Binding
	Quit  key.Binding
	Help  key.Binding
}

// ShortHelp returns keybindings to be shown in the mini help view
func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Tab, k.Quit, k.Help}
}

// FullHelp returns keybindings for the expanded help view
func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Left, k.Right},
		{k.Tab, k.Quit, k.Help},
	}
}

var keys = keyMap{
	Up: key.NewBinding(
		key.WithKeys("up", "k"),
		key.WithHelp("↑/k", "scroll up"),
	),
	Down: key.NewBinding(
		key.WithKeys("down", "j"),
		key.WithHelp("↓/j", "scroll down"),
	),
	Left: key.NewBinding(
		key.WithKeys("left", "h"),
		key.WithHelp("←/h", "previous probe"),
	),
	Right: key.NewBinding(
		key.WithKeys("right", "l"),
		key.WithHelp("→/l", "next probe"),
	),
	Tab: key.NewBinding(
		key.WithKeys("tab"),
		key.WithHelp("tab", "switch focus"),
	),
	Quit: key.NewBinding(
		key.WithKeys("q", "ctrl+c"),
		key.WithHelp("q", "quit"),
	),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "toggle help"),
	),
}

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	summaryTitleStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#FAFAFA")).
				Background(lipgloss.Color("#5A67D8")).
				Padding(0, 1)

	probeTitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#000000")).
			Background(lipgloss.Color("#10B981")).
			Padding(0, 1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FBBF24"))

	hopStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E5E7EB"))

	ipStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#60A5FA"))

	statsGoodStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#34D399"))

	statsWarningStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#FBBF24"))

	statsBadStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F87171"))

	borderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#626262"))
)

type cellAlignment int

const (
	alignLeft cellAlignment = iota
	alignRight
)

func formatCell(value string, width int, alignment cellAlignment) string {
	if alignment == alignRight {
		return fmt.Sprintf("%*s", width, value)
	}
	return fmt.Sprintf("%-*s", width, value)
}

type paneFocus int

const (
	focusSummary paneFocus = iota
	focusDetails
)

func truncateToWidth(value string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(value) <= width {
		return value
	}
	return lipgloss.NewStyle().Width(width).Render(value)
}

func (m *tuiModel) changeSelectedProbe(delta int) {
	m.mu.RLock()
	numProbes := len(m.probes)
	m.mu.RUnlock()
	if numProbes == 0 {
		return
	}

	current := int(m.selectedProbe)
	next := (current + delta) % numProbes
	if next < 0 {
		next += numProbes
	}

	if next != current {
		m.detailScroll = 0
	}
	m.selectedProbe = uint16(next)
}

func (m *tuiModel) scrollDetails(delta int) {
	next := m.detailScroll + delta
	next = max(next, 0)
	m.detailScroll = next
}

func (m *tuiModel) ensureDetailVisible() {
	if m.focus != focusDetails {
		return
	}
	if m.detailScroll < 0 {
		m.detailScroll = 0
	}
	// Reset to top when entering detail view so newest rows are visible
	m.detailScroll = 0
}

// NewBubbleTUIOutput creates a new Bubble Tea TUI output
func NewBubbleTUIOutput(info OutputInfo) *BubbleTUIOutput {
	updateCh := make(chan tuiUpdateMsg, 100)
	quitCh := make(chan struct{})

	model := &tuiModel{
		probes:        make(map[uint16]*ProbeStats),
		destination:   info.destination,
		protocol:      info.protocol,
		srcPort:       info.srcPort,
		dstPort:       info.dstPort,
		startTime:     time.Now(),
		selectedProbe: 0,
		focus:         focusSummary,
		help:          help.New(),
		keys:          keys,
		updateCh:      updateCh,
		quitCh:        quitCh,
	}

	// Initialize all probe stats
	for i := uint16(0); i < info.parallelProbes; i++ {
		model.probes[i] = &ProbeStats{
			ProbeID: i,
			Hops:    make(map[uint8]*HopStats),
		}
	}

	tui := &BubbleTUIOutput{
		model:    model,
		updateCh: updateCh,
		quitCh:   quitCh,
		doneCh:   make(chan struct{}),
	}

	return tui
}

// Start initializes and starts the Bubble Tea program
func (b *BubbleTUIOutput) Start() {
	// Create program with proper cleanup options
	doneCh := make(chan struct{})
	b.doneCh = doneCh
	b.program = tea.NewProgram(
		b.model,
		tea.WithAltScreen(),       // Use alternate screen buffer
		tea.WithMouseCellMotion(), // Proper mouse handling cleanup
	)

	go func() {
		// Ensure cleanup happens even if there's a panic
		defer func() {
			close(doneCh)
			if r := recover(); r != nil {
				log.Errorf("TUI panic: %v", r)
				// Force cleanup
				b.program.Kill()
			}
		}()

		if _, err := b.program.Run(); err != nil {
			log.Errorf("Error running TUI: %v", err)
		}
	}()
}

// QuitChan returns the channel that signals when the user quits the TUI
func (b *BubbleTUIOutput) QuitChan() <-chan struct{} {
	return b.quitCh
}

// UpdateHop implements the Output interface
func (b *BubbleTUIOutput) UpdateHop(probeID uint16, ttl uint8, hopStats HopStats) {
	b.mu.Lock()
	defer b.mu.Unlock()

	select {
	case b.updateCh <- tuiUpdateMsg{
		probeID:  probeID,
		ttl:      ttl,
		hopStats: hopStats,
	}:
	default:
		// Channel full, skip update
	}
}

// CompleteProbe implements the Output interface
func (b *BubbleTUIOutput) CompleteProbe(probeID uint16, stats ProbeStats) {
	// Updates are handled through UpdateHop
}

// Close implements the Output interface
func (b *BubbleTUIOutput) Close() error {
	b.mu.Lock()
	program := b.program
	doneCh := b.doneCh
	quitCh := b.quitCh
	b.mu.Unlock()

	if program != nil {
		// Request graceful shutdown
		program.Quit()

		if doneCh != nil {
			select {
			case <-doneCh:
				// Clean exit
			case <-time.After(500 * time.Millisecond):
				// Force cleanup if it takes too long
				program.Kill()
				<-doneCh
			}
		}
	}

	if quitCh != nil {
		select {
		case <-quitCh:
			// Already closed
		default:
			close(quitCh)
		}
	}

	b.mu.Lock()
	b.program = nil
	b.doneCh = nil
	b.mu.Unlock()

	return nil
}

// Init is the initial I/O for Bubble Tea
func (m *tuiModel) Init() tea.Cmd {
	return tea.Batch(
		tickCmd(),
		waitForUpdate(m.updateCh),
	)
}

// Update handles messages and updates the model
func (m *tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Quit):
			// Signal quit to the main program
			select {
			case m.quitCh <- struct{}{}:
			default:
			}
			return m, tea.Quit
		case key.Matches(msg, m.keys.Help):
			m.help.ShowAll = !m.help.ShowAll
		case key.Matches(msg, m.keys.Tab):
			if m.focus == focusSummary {
				m.focus = focusDetails
				m.ensureDetailVisible()
			} else {
				m.focus = focusSummary
			}
		case key.Matches(msg, m.keys.Up):
			if m.focus == focusSummary {
				m.changeSelectedProbe(-1)
			} else {
				m.scrollDetails(-1)
			}
		case key.Matches(msg, m.keys.Down):
			if m.focus == focusSummary {
				m.changeSelectedProbe(1)
			} else {
				m.scrollDetails(1)
			}
		case key.Matches(msg, m.keys.Right):
			if m.focus == focusSummary {
				m.changeSelectedProbe(1)
			}
		case key.Matches(msg, m.keys.Left):
			if m.focus == focusSummary {
				m.changeSelectedProbe(-1)
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.help.Width = msg.Width

	case tuiUpdateMsg:
		m.mu.Lock()
		if probe, exists := m.probes[msg.probeID]; exists {
			if probe.Hops == nil {
				probe.Hops = make(map[uint8]*HopStats)
			}
			// Deep copy the hop stats
			hopCopy := msg.hopStats
			probe.Hops[msg.ttl] = &hopCopy
		}
		m.mu.Unlock()
		return m, waitForUpdate(m.updateCh)

	case tickMsg:
		return m, tickCmd()
	}

	return m, nil
}

// View renders the UI
func (m *tuiModel) View() string {
	if m.width == 0 {
		return "Initializing..."
	}

	var b strings.Builder

	// Title bar
	elapsed := time.Since(m.startTime)
	title := fmt.Sprintf(" ECMP Traceroute to %s | Protocol: %s | Port: %d | Elapsed: %s ",
		m.destination, m.protocol, m.dstPort, elapsed.Round(time.Second))
	b.WriteString(titleStyle.Width(m.width).Render(title))
	b.WriteString("\n")

	// Calculate available height for content
	helpHeight := lipgloss.Height(m.help.View(m.keys))
	contentHeight := m.height - 4 - helpHeight // title + spacing + help

	// Split view: summary on top, detailed probe view below
	summaryHeight := min(contentHeight/3, 15)
	probeHeight := contentHeight - summaryHeight - 2

	// Render summary pane
	summary := m.renderSummary(summaryHeight)
	b.WriteString(summary)
	b.WriteString("\n")

	// Render selected probe details
	probeView := m.renderProbeDetails(m.selectedProbe, probeHeight)
	b.WriteString(probeView)

	// Help
	b.WriteString("\n")
	b.WriteString(helpStyle.Render(m.help.View(m.keys)))

	return b.String()
}

// renderSummary renders the summary pane showing all probes
func (m *tuiModel) renderSummary(maxHeight int) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var b strings.Builder

	// Calculate unique paths
	uniquePaths := make(map[string]bool)
	for _, probe := range m.probes {
		hash := calculatePathHash(probe)
		uniquePaths[hash] = true
	}

	title := summaryTitleStyle.Render(fmt.Sprintf(" Summary (%d probes, %d unique paths) ", len(m.probes), len(uniquePaths)))
	b.WriteString(title)
	b.WriteString("\n\n")

	// Header
	header := fmt.Sprintf("  %-6s %7s %-9s %4s %8s %8s %8s %8s %8s",
		"Probe", "SrcPort", " Path", "Hops", "Loss%", "Avg(ms)", "Min(ms)", "Max(ms)", "StdDev")
	b.WriteString(headerStyle.Render(truncateToWidth(header, m.width-4)))
	b.WriteString("\n")

	// Get sorted probe IDs
	probeIDs := make([]uint16, 0, len(m.probes))
	for id := range m.probes {
		probeIDs = append(probeIDs, id)
	}
	slices.Sort(probeIDs)

	visibleRows := maxHeight - 3
	visibleRows = max(visibleRows, 1)

	selectedIndex := 0
	for idx, id := range probeIDs {
		if id == m.selectedProbe {
			selectedIndex = idx
			break
		}
	}

	maxScroll := 0
	if len(probeIDs) > visibleRows {
		maxScroll = len(probeIDs) - visibleRows
	}
	if m.summaryScroll > maxScroll {
		m.summaryScroll = maxScroll
	}
	if selectedIndex < m.summaryScroll {
		m.summaryScroll = selectedIndex
	}
	if selectedIndex >= m.summaryScroll+visibleRows {
		m.summaryScroll = selectedIndex - visibleRows + 1
	}

	contentWidth := m.width - 4
	contentWidth = max(contentWidth, 0)
	start := m.summaryScroll
	end := start + visibleRows
	if end > len(probeIDs) {
		end = len(probeIDs)
	}

	for _, id := range probeIDs[start:end] {
		probe := m.probes[id]
		stats := calculateProbeAggregateStats(probe)

		style := hopStyle
		prefix := "  "
		if id == m.selectedProbe {
			style = style.Bold(true).Foreground(lipgloss.Color("#10B981"))
			if m.focus == focusSummary {
				style = style.Background(lipgloss.Color("#064E3B")).Foreground(lipgloss.Color("#ECFDF5"))
			}
			prefix = "► "
		}

		// Color code based on loss percentage
		lossStyle := statsGoodStyle
		if stats.LossPct > 10 {
			lossStyle = statsWarningStyle
		}
		if stats.LossPct > 25 {
			lossStyle = statsBadStyle
		}

		srcPort := m.srcPort + id
		cells := []string{
			formatCell(fmt.Sprintf("#%d", id), 6, alignLeft),
			formatCell(fmt.Sprintf("%d", srcPort), 7, alignRight),
			formatCell(stats.PathHash, 9, alignRight),
			formatCell(fmt.Sprintf("%d", stats.NumHops), 4, alignRight),
			formatCell(fmt.Sprintf("%.1f%%", stats.LossPct), 8, alignRight),
			formatCell(fmt.Sprintf("%.2f", stats.AvgRTT), 8, alignRight),
			formatCell(fmt.Sprintf("%.2f", stats.MinRTT), 8, alignRight),
			formatCell(fmt.Sprintf("%.2f", stats.MaxRTT), 8, alignRight),
			formatCell(fmt.Sprintf("%.2f", stats.StdDev), 8, alignRight),
		}

		cells[4] = lossStyle.Render(cells[4])
		line := prefix + strings.Join(cells, " ")
		line = truncateToWidth(line, contentWidth)
		b.WriteString(style.Render(line))
		b.WriteString("\n")
	}

	summaryContainer := borderStyle
	if m.focus == focusSummary {
		summaryContainer = summaryContainer.BorderForeground(lipgloss.Color("#34D399"))
	}

	return summaryContainer.Width(m.width - 2).Render(b.String())
}

// renderProbeDetails renders detailed hop-by-hop view for a specific probe
func (m *tuiModel) renderProbeDetails(probeID uint16, maxHeight int) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	probe, exists := m.probes[probeID]
	if !exists {
		return borderStyle.Width(m.width - 4).Render("No data for probe")
	}

	var b strings.Builder

	srcPort := m.srcPort + m.selectedProbe
	focusLabel := ""
	if m.focus == focusDetails {
		focusLabel = " [detail focus]"
	}
	title := probeTitleStyle.Render(fmt.Sprintf(" ► PROBE #%d ◄ - Source Port: %d%s ", probeID, srcPort, focusLabel))
	b.WriteString(title)
	b.WriteString("\n\n")

	contentWidth := m.width - 4
	contentWidth = max(contentWidth, 20)

	fixedColumns := 65
	hostWidth := contentWidth - fixedColumns
	hostWidth = max(hostWidth, 10)

	headerFmt := fmt.Sprintf("%%-%ds %%-%ds %%8s %%6s %%8s %%8s %%8s %%8s %%8s", 3, hostWidth)
	header := fmt.Sprintf(headerFmt,
		"TTL", "Host", "Loss%", "Sent", "Last", "Avg", "Best", "Worst", "StDev")
	b.WriteString(headerStyle.Render(truncateToWidth(header, contentWidth)))
	b.WriteString("\n")

	ttls := make([]uint8, 0, len(probe.Hops))
	for ttl := range probe.Hops {
		ttls = append(ttls, ttl)
	}
	slices.Sort(ttls)

	bodyLines := make([]string, 0)

	for _, ttl := range ttls {
		hop := probe.Hops[ttl]

		ip := hop.CurrentIP
		if ip == "" && len(hop.IPs) > 0 {
			for ipAddr := range hop.IPs {
				ip = ipAddr
				break
			}
		}

		ipStats := hop.IPs[ip]
		if ipStats == nil {
			continue
		}

		sent := ipStats.Responses + ipStats.Lost
		lossPct := hop.LossPct

		lossStyle := statsGoodStyle
		if lossPct > 10 {
			lossStyle = statsWarningStyle
		}
		if lossPct > 25 {
			lossStyle = statsBadStyle
		}

		ipDisplay := ip
		if ip == "" || ip == "???" {
			ipDisplay = "???"
		} else if ipStats.PTR != "" {
			ipDisplay = fmt.Sprintf("%s (%s)", ipStats.PTR, ip)
		}

		if len(ipDisplay) > hostWidth {
			ipDisplay = ipDisplay[:hostWidth-3] + "..."
		}

		cells := []string{
			formatCell(fmt.Sprintf("%d", ttl), 3, alignLeft),
			formatCell(ipDisplay, hostWidth, alignLeft),
			formatCell(fmt.Sprintf("%.1f%%", lossPct), 8, alignRight),
			formatCell(fmt.Sprintf("%d", sent), 6, alignRight),
			formatCell(fmt.Sprintf("%.2f", float64(ipStats.Last)/1000.0), 8, alignRight),
			formatCell(fmt.Sprintf("%.2f", float64(ipStats.Avg)/1000.0), 8, alignRight),
			formatCell(fmt.Sprintf("%.2f", float64(ipStats.Min)/1000.0), 8, alignRight),
			formatCell(fmt.Sprintf("%.2f", float64(ipStats.Max)/1000.0), 8, alignRight),
			formatCell(fmt.Sprintf("%.2f", ipStats.StdDev/1000.0), 8, alignRight),
		}

		if ip != "" && ip != "???" {
			cells[1] = ipStyle.Render(cells[1])
		} else {
			cells[1] = ipStyle.Foreground(lipgloss.Color("#6B7280")).Render(cells[1])
		}
		cells[2] = lossStyle.Render(cells[2])

		line := strings.Join(cells, " ")
		line = truncateToWidth(line, contentWidth)
		bodyLines = append(bodyLines, hopStyle.Render(line))

		if len(hop.IPs) > 1 {
			for altIP := range hop.IPs {
				if altIP == ip {
					continue
				}
				altStats := hop.IPs[altIP]
				if altStats == nil {
					continue
				}

				altIPDisplay := altIP
				if altStats.PTR != "" {
					altIPDisplay = fmt.Sprintf("%s (%s)", altStats.PTR, altIP)
				}

				altValue := "↳ " + altIPDisplay
				if len(altValue) > hostWidth {
					altValue = altValue[:hostWidth-3] + "..."
				}

				altLossStyle := statsGoodStyle
				if altStats.LossPct > 10 {
					altLossStyle = statsWarningStyle
				}
				if altStats.LossPct > 25 {
					altLossStyle = statsBadStyle
				}

				cells := []string{
					formatCell("", 3, alignLeft),
					formatCell(altValue, hostWidth, alignLeft),
					formatCell(fmt.Sprintf("%.1f%%", altStats.LossPct), 8, alignRight),
					formatCell(fmt.Sprintf("%d", altStats.Responses+altStats.Lost), 6, alignRight),
					formatCell(fmt.Sprintf("%.2f", float64(altStats.Last)/1000.0), 8, alignRight),
					formatCell(fmt.Sprintf("%.2f", float64(altStats.Avg)/1000.0), 8, alignRight),
					formatCell(fmt.Sprintf("%.2f", float64(altStats.Min)/1000.0), 8, alignRight),
					formatCell(fmt.Sprintf("%.2f", float64(altStats.Max)/1000.0), 8, alignRight),
					formatCell(fmt.Sprintf("%.2f", altStats.StdDev/1000.0), 8, alignRight),
				}

				cells[1] = ipStyle.Foreground(lipgloss.Color("#9CA3AF")).Render(cells[1])
				cells[2] = altLossStyle.Render(cells[2])

				line := strings.Join(cells, " ")
				line = truncateToWidth(line, contentWidth)
				bodyLines = append(bodyLines, hopStyle.Foreground(lipgloss.Color("#9CA3AF")).Render(line))
			}
		}
	}

	visibleLines := maxHeight - 4
	visibleLines = max(visibleLines, 0)

	maxScroll := 0
	if visibleLines > 0 && len(bodyLines) > visibleLines {
		maxScroll = len(bodyLines) - visibleLines
	}
	m.detailScroll = min(m.detailScroll, maxScroll)

	start := m.detailScroll
	start = min(start, len(bodyLines))

	end := start + visibleLines
	end = min(end, len(bodyLines))

	for _, line := range bodyLines[start:end] {
		b.WriteString(line)
		b.WriteString("\n")
	}

	detailContainer := borderStyle
	if m.focus == focusDetails {
		detailContainer = detailContainer.BorderForeground(lipgloss.Color("#34D399"))
	}

	return detailContainer.Width(m.width - 2).Render(b.String())
}

// Helper types for aggregate stats
type probeAggregateStats struct {
	NumHops  int
	LossPct  float64
	AvgRTT   float64
	MinRTT   float64
	MaxRTT   float64
	StdDev   float64
	PathHash string // CRC32 hash of the path (8 hex chars)
}

// calculatePathHash computes a CRC32 hash of the network path
func calculatePathHash(probe *ProbeStats) string {
	if probe == nil || len(probe.Hops) == 0 {
		return "00000000"
	}

	// Get sorted TTLs to ensure consistent ordering
	ttls := make([]uint8, 0, len(probe.Hops))
	for ttl := range probe.Hops {
		ttls = append(ttls, ttl)
	}
	slices.Sort(ttls)

	// Build path string from CurrentIP at each hop
	var pathBuilder strings.Builder
	for _, ttl := range ttls {
		hop := probe.Hops[ttl]
		if hop.CurrentIP != "" {
			pathBuilder.WriteString(hop.CurrentIP)
			pathBuilder.WriteString("|")
		}
	}

	// Calculate CRC32 hash
	pathString := pathBuilder.String()
	hash := crc32.ChecksumIEEE([]byte(pathString))

	// Return as 8-character hex string
	return fmt.Sprintf("%08x", hash)
}

// calculateProbeAggregateStats calculates aggregate stats for a probe
func calculateProbeAggregateStats(probe *ProbeStats) probeAggregateStats {
	stats := probeAggregateStats{
		NumHops: len(probe.Hops),
	}
	minRTTSet := false

	if len(probe.Hops) == 0 {
		stats.MinRTT = 0
		return stats
	}

	var totalRTT float64
	var count int
	var maxTTL uint8 = 0

	// Find the highest TTL (destination hop)
	for ttl := range probe.Hops {
		maxTTL = max(maxTTL, ttl)
	}

	// Calculate all stats from the destination hop only
	if destHop, exists := probe.Hops[maxTTL]; exists {
		// Calculate loss percentage
		if destHop.Received+destHop.Lost > 0 {
			stats.LossPct = (float64(destHop.Lost) / float64(destHop.Received+destHop.Lost)) * 100
		}

		var totalStdDev float64
		// Aggregate RTT stats across all IPs at the destination hop
		for _, ipStats := range destHop.IPs {
			if ipStats.Responses > 0 {
				avgRTT := float64(ipStats.Avg) / 1000.0
				totalRTT += avgRTT
				count++

				minRTT := float64(ipStats.Min) / 1000.0
				maxRTT := float64(ipStats.Max) / 1000.0

				if !minRTTSet || minRTT < stats.MinRTT {
					stats.MinRTT = minRTT
					minRTTSet = true
				}
				if maxRTT > stats.MaxRTT {
					stats.MaxRTT = maxRTT
				}

				// Accumulate StdDev (already calculated per IP in microseconds)
				totalStdDev += ipStats.StdDev / 1000.0
			}
		}

		if count > 0 {
			stats.AvgRTT = totalRTT / float64(count)
			// Average the StdDev across IPs
			stats.StdDev = totalStdDev / float64(count)
		}
	}

	if !minRTTSet {
		stats.MinRTT = 0
	}

	// Calculate path hash
	stats.PathHash = calculatePathHash(probe)

	return stats
}

// waitForUpdate waits for the next update message
func waitForUpdate(updateCh chan tuiUpdateMsg) tea.Cmd {
	return func() tea.Msg {
		return <-updateCh
	}
}

// tickCmd returns a command that sends a tick message periodically
func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}
