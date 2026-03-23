package output

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/tkjaer/etr/internal/shared"
)

// BubbleTUIOutput is an MTR-like TUI using Bubble Tea
type BubbleTUIOutput struct {
	mu       sync.RWMutex
	program  *tea.Program
	model    *tuiModel
	updateCh chan tuiUpdateMsg
	quitCh   chan struct{}
	doneCh   chan struct{}

	signalMu        sync.Mutex
	lastSignal      time.Time
	refreshInterval time.Duration
}

// tuiUpdateMsg is sent when hop stats are updated
type tuiUpdateMsg struct{}

// tickMsg is sent periodically to refresh the display
type tickMsg time.Time

// tuiModel holds the Bubble Tea model state
type tuiModel struct {
	// Data
	probes          map[uint16]*shared.ProbeStats
	mu              sync.RWMutex
	destination     string
	protocol        string
	dstPort         uint16
	srcPort         uint16
	startTime       time.Time
	hashAlgorithm   string
	refreshInterval time.Duration
	noStyle         bool

	// Discovery mode
	discoverMode   bool
	discoMode      bool
	discoFrame     int
	discoveryStats shared.DiscoveryStats

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
	value = strings.ReplaceAll(value, "\n", " ")
	if lipgloss.Width(value) <= width {
		return value
	}
	if width <= 3 {
		return strings.Repeat(".", width)
	}

	targetWidth := width - 3
	var b strings.Builder
	currentWidth := 0
	for _, r := range value {
		runeWidth := lipgloss.Width(string(r))
		if currentWidth+runeWidth > targetWidth {
			break
		}
		b.WriteRune(r)
		currentWidth += runeWidth
	}

	return b.String() + "..."
}

func padToWidth(value string, width int) string {
	if width <= 0 {
		return ""
	}
	lines := strings.Split(value, "\n")
	for i, line := range lines {
		lineWidth := lipgloss.Width(line)
		if lineWidth < width {
			lines[i] = line + strings.Repeat(" ", width-lineWidth)
		}
	}
	return strings.Join(lines, "\n")
}

func formatHopDisplay(ip, ptr, asn string) string {
	if ip == "" || ip == "???" {
		return "???"
	}

	switch {
	case ptr != "" && asn != "":
		return fmt.Sprintf("%s (%s) [%s]", ptr, ip, asn)
	case ptr != "":
		return fmt.Sprintf("%s (%s)", ptr, ip)
	case asn != "":
		return fmt.Sprintf("%s [%s]", ip, asn)
	default:
		return ip
	}
}

func (m *tuiModel) render(style lipgloss.Style, value string) string {
	if m.noStyle {
		return value
	}
	return style.Render(value)
}

func (m *tuiModel) renderWidth(style lipgloss.Style, width int, value string) string {
	if m.noStyle {
		return padToWidth(truncateToWidth(value, width), width)
	}
	return style.Width(width).Render(value)
}

func (m *tuiModel) renderContainer(style lipgloss.Style, width int, value string) string {
	if m.noStyle {
		return padToWidth(value, width)
	}
	return style.Width(width).Render(value)
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
func NewBubbleTUIOutput(info shared.OutputInfo) *BubbleTUIOutput {
	updateCh := make(chan tuiUpdateMsg, 100)
	quitCh := make(chan struct{})

	model := &tuiModel{
		probes:          make(map[uint16]*shared.ProbeStats),
		destination:     info.Destination,
		protocol:        info.Protocol,
		srcPort:         info.SrcPort,
		dstPort:         info.DstPort,
		startTime:       time.Now(),
		hashAlgorithm:   info.HashAlgorithm,
		refreshInterval: info.TUIRefresh,
		noStyle:         info.NoStyle,
		discoverMode:    info.DiscoverMode,
		discoMode:       info.DiscoMode,
		selectedProbe:   0,
		focus:           focusSummary,
		help:            help.New(),
		keys:            keys,
		updateCh:        updateCh,
		quitCh:          quitCh,
	}

	// Initialize all probe stats
	probes := make(map[uint16]*shared.ProbeStats)
	for i := uint16(0); i < info.ParallelProbes; i++ {
		probes[i] = &shared.ProbeStats{
			ProbeID: i,
			Hops:    make(map[uint8]*shared.HopStats),
		}
	}
	model.probes = probes

	tui := &BubbleTUIOutput{
		model:           model,
		updateCh:        updateCh,
		quitCh:          quitCh,
		doneCh:          make(chan struct{}),
		refreshInterval: info.TUIRefresh,
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
		tea.WithAltScreen(), // Use alternate screen buffer
	)

	go func() {
		// Ensure cleanup happens even if there's a panic
		defer func() {
			close(doneCh)
			if r := recover(); r != nil {
				slog.Error("TUI panic", "error", r)
				// Force cleanup
				b.program.Kill()
			}
		}()

		if _, err := b.program.Run(); err != nil {
			slog.Error("Error running TUI", "error", err)
		}
	}()
}

// QuitChan returns the channel that signals when the user quits the TUI
func (b *BubbleTUIOutput) QuitChan() <-chan struct{} {
	return b.quitCh
}

// UpdateHop implements the Output interface
func (b *BubbleTUIOutput) UpdateHop(probeID uint16, ttl uint8, hopStats shared.HopStats) {
	// Snapshot pointers so we don't hold b.mu while updating model state.
	b.mu.RLock()
	model := b.model
	updateCh := b.updateCh
	b.mu.RUnlock()
	if model == nil {
		return
	}

	model.mu.Lock()
	if _, exists := model.probes[probeID]; !exists {
		// Auto-create probe entry for dynamically spawned discovery probes
		model.probes[probeID] = &shared.ProbeStats{
			ProbeID: probeID,
			Hops:    make(map[uint8]*shared.HopStats),
		}
	}
	if probe, exists := model.probes[probeID]; exists {
		if probe.Hops == nil {
			probe.Hops = make(map[uint8]*shared.HopStats)
		}
		hopCopy := hopStats
		probe.Hops[ttl] = &hopCopy
	}
	model.mu.Unlock()

	if updateCh != nil && b.shouldSignal() {
		select {
		case updateCh <- tuiUpdateMsg{}:
		default:
		}
	}
}

// CompleteProbe implements the Output interface
func (b *BubbleTUIOutput) CompleteProbe(probeID uint16, stats shared.ProbeStats) {
	// Updates are handled through UpdateHop
}

func (b *BubbleTUIOutput) DeleteHops(probeID uint16, ttls []uint8) {
	if len(ttls) == 0 {
		return
	}

	// Snapshot pointers so we don't hold b.mu while updating model state.
	b.mu.RLock()
	model := b.model
	updateCh := b.updateCh
	b.mu.RUnlock()
	if model == nil {
		return
	}

	model.mu.Lock()
	if probe, exists := model.probes[probeID]; exists {
		for _, ttl := range ttls {
			delete(probe.Hops, ttl)
		}
	}
	model.mu.Unlock()

	if updateCh != nil && b.shouldSignal() {
		select {
		case updateCh <- tuiUpdateMsg{}:
		default:
		}
	}
}

func (b *BubbleTUIOutput) shouldSignal() bool {
	if b.refreshInterval <= 0 {
		return true
	}
	now := time.Now()
	b.signalMu.Lock()
	defer b.signalMu.Unlock()
	if now.Sub(b.lastSignal) >= b.refreshInterval {
		b.lastSignal = now
		return true
	}
	return false
}

func (b *BubbleTUIOutput) CompleteProbeRun(run *shared.ProbeRun) {
	// No special handling needed — stats are tracked via UpdateHop
}

// UpdateDiscoveryStats receives live discovery progress from the probe manager.
func (b *BubbleTUIOutput) UpdateDiscoveryStats(stats shared.DiscoveryStats) {
	b.mu.RLock()
	model := b.model
	updateCh := b.updateCh
	b.mu.RUnlock()
	if model == nil {
		return
	}
	model.mu.Lock()
	model.discoveryStats = stats
	model.mu.Unlock()
	if updateCh != nil && b.shouldSignal() {
		select {
		case updateCh <- tuiUpdateMsg{}:
		default:
		}
	}
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
		tickCmd(m.refreshInterval),
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
		return m, tea.ClearScreen

	case tuiUpdateMsg:
		return m, waitForUpdate(m.updateCh)

	case tickMsg:
		return m, tickCmd(m.refreshInterval)
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
	var title string
	if m.discoverMode {
		title = fmt.Sprintf(" DISCOVERY — %s | %s port %d | Elapsed: %s ",
			m.destination, m.protocol, m.dstPort, elapsed.Round(time.Second))
		if m.discoMode {
			title = fmt.Sprintf(" 🪩 DISCO — %s | %s port %d | Elapsed: %s ",
				m.destination, m.protocol, m.dstPort, elapsed.Round(time.Second))
		}
	} else {
		title = fmt.Sprintf(" ECMP Traceroute to %s | Protocol: %s | Port: %d | Elapsed: %s ",
			m.destination, m.protocol, m.dstPort, elapsed.Round(time.Second))
	}
	if m.discoMode {
		// Easter egg: --disco renders a rainbow wave across the title bar 🪩
		rainbow := []string{"#FF0055", "#FF4400", "#FF9900", "#FFDD00", "#88FF00", "#00FF88", "#00DDFF", "#0088FF", "#4400FF", "#9900FF", "#FF00AA"}
		// Pad title to full width
		for lipgloss.Width(title) < m.width {
			title += " "
		}
		// Render each character with a shifted color for a moving wave
		var discoBar strings.Builder
		frame := m.discoFrame / 3 // slow down: advance wave every 3 renders
		for i, ch := range title {
			idx := (i/2 + frame) % len(rainbow)
			style := lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#FFFFFF")).
				Background(lipgloss.Color(rainbow[idx]))
			discoBar.WriteString(style.Render(string(ch)))
		}
		m.discoFrame++
		b.WriteString(discoBar.String())
	} else {
		b.WriteString(m.renderWidth(titleStyle, m.width, title))
	}
	b.WriteString("\n")

	// Discovery progress strip (only in discovery mode)
	discoveryStripHeight := 0
	if m.discoverMode {
		b.WriteString(m.renderDiscoveryProgress())
		b.WriteString("\n")
		discoveryStripHeight = 1
	}

	// Help is always 1 line
	helpHeight := 1
	separatorHeight := 6
	if m.noStyle {
		separatorHeight = 2
	}
	contentHeight := m.height - separatorHeight - helpHeight - discoveryStripHeight

	// Split view: summary on top, detailed probe view below.
	// Size each pane to fit its content; when both need more than available,
	// share proportionally with a minimum of 5 rows each.
	m.mu.RLock()
	probeCount := len(m.probes)
	selectedHops := 0
	if probe, ok := m.probes[m.selectedProbe]; ok {
		selectedHops = len(probe.Hops)
	}
	m.mu.RUnlock()

	summaryWant := probeCount + 5 // rows + header + border
	detailWant := selectedHops + 5 // hops + header + border
	minPane := 5

	totalWant := summaryWant + detailWant + 1
	var summaryHeight, probeHeight int
	if totalWant <= contentHeight {
		// Both fit — give each what it needs, extra goes to detail
		summaryHeight = summaryWant
		probeHeight = contentHeight - summaryHeight - 1
	} else {
		// Not enough room — share proportionally, min 5 each
		ratio := float64(summaryWant) / float64(totalWant)
		summaryHeight = int(ratio * float64(contentHeight-1))
		summaryHeight = max(summaryHeight, minPane)
		summaryHeight = min(summaryHeight, contentHeight-1-minPane)
		probeHeight = contentHeight - summaryHeight - 1
	}

	// Render summary pane
	summary := m.renderNormalSummary(summaryHeight)
	b.WriteString(summary)
	b.WriteString("\n")

	// Render selected probe details
	probeView := m.renderLiveProbeDetails(m.selectedProbe, probeHeight)
	b.WriteString(probeView)

	// Help
	b.WriteString("\n")
	b.WriteString(m.render(helpStyle, m.help.View(m.keys)))

	return b.String()
}

// renderDiscoveryProgress renders a one-line status strip for discovery mode.
func (m *tuiModel) renderDiscoveryProgress() string {
	m.mu.RLock()
	stats := m.discoveryStats
	// Count unique paths across all probes
	uniquePaths := make(map[string]struct{})
	for _, probe := range m.probes {
		hash := shared.CalculatePathHashFromProbe(probe, m.hashAlgorithm)
		if hash != "" && hash != "00000000" {
			uniquePaths[hash] = struct{}{}
		}
	}
	paths := len(uniquePaths)
	m.mu.RUnlock()

	// Build progress bar for flow budget
	var flowPart string
	if stats.FlowBudget == 0 {
		flowPart = fmt.Sprintf("Flows: %d/∞", stats.FlowsUsed)
	} else {
		barWidth := 12
		filled := int(float64(stats.FlowsUsed) / float64(stats.FlowBudget) * float64(barWidth))
		if filled > barWidth {
			filled = barWidth
		}
		bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
		flowPart = fmt.Sprintf("Flows: %d/%d [%s]", stats.FlowsUsed, stats.FlowBudget, bar)
	}

	noNewPart := fmt.Sprintf("No new paths: %d/%d rounds", stats.NoNewPathsCount, stats.NoNewPathsTarget)
	progressLine := fmt.Sprintf("  %d path(s) found   %s   Round %d   %s  ",
		paths, flowPart, stats.RoundsCompleted, noNewPart)
	return m.renderWidth(titleStyle, m.width, progressLine)
}

// renderNormalSummary renders the per-probe summary pane.
func (m *tuiModel) renderNormalSummary(maxHeight int) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var b strings.Builder

	// Calculate unique paths and track which probeID first observed each hash
	pathFirstProbe := make(map[string]uint16) // hash -> lowest probeID
	pathCount := make(map[string]int)
	for id, probe := range m.probes {
		hash := shared.CalculatePathHashFromProbe(probe, m.hashAlgorithm)
		pathCount[hash]++
		if first, exists := pathFirstProbe[hash]; !exists || id < first {
			pathFirstProbe[hash] = id
		}
	}
	uniqueCount := len(pathCount)

	title := m.render(summaryTitleStyle, fmt.Sprintf(" Summary (%d probes, %d unique paths) ", len(m.probes), uniqueCount))
	b.WriteString(title)
	b.WriteString("\n\n")

	// Header
	header := fmt.Sprintf("  %-6s %6s %-8s %3s %6s %7s %7s %7s %7s",
		"Probe", "SrcPort", " Path", "Hops", "Loss%", "Avg(ms)", "Min(ms)", "Max(ms)", "StdDev")
	b.WriteString(m.render(headerStyle, truncateToWidth(header, m.width-4)))
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
	if m.noStyle {
		contentWidth = m.width
	}
	contentWidth = max(contentWidth, 0)
	start := m.summaryScroll
	end := start + visibleRows
	if end > len(probeIDs) {
		end = len(probeIDs)
	}

	for _, id := range probeIDs[start:end] {
		probe := m.probes[id]
		stats := calculateProbeAggregateStats(probe, m.hashAlgorithm)

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
		pathLabel := fmt.Sprintf("%.7s", stats.PathHash)
		if pathCount[stats.PathHash] > 1 && pathFirstProbe[stats.PathHash] != id {
			pathLabel = fmt.Sprintf("%.5s =", stats.PathHash)
		}
		cells := []string{
			formatCell(fmt.Sprintf("#%d", id), 6, alignLeft),
			formatCell(fmt.Sprintf("%d", srcPort), 6, alignRight),
			formatCell(pathLabel, 8, alignRight),
			formatCell(fmt.Sprintf("%d", stats.NumHops), 3, alignRight),
			formatCell(fmt.Sprintf("%.1f%%", stats.LossPct), 6, alignRight),
			formatCell(fmt.Sprintf("%.2f", stats.AvgRTT), 7, alignRight),
			formatCell(fmt.Sprintf("%.2f", stats.MinRTT), 7, alignRight),
			formatCell(fmt.Sprintf("%.2f", stats.MaxRTT), 7, alignRight),
			formatCell(fmt.Sprintf("%.2f", stats.StdDev), 7, alignRight),
		}

		cells[4] = m.render(lossStyle, cells[4])
		line := prefix + strings.Join(cells, " ")
		line = truncateToWidth(line, contentWidth)
		b.WriteString(m.render(style, line))
		b.WriteString("\n")
	}

	summaryContainer := borderStyle
	if m.focus == focusSummary {
		summaryContainer = summaryContainer.BorderForeground(lipgloss.Color("#34D399"))
	}

	containerWidth := m.width - 2
	if m.noStyle {
		containerWidth = m.width
	}
	return m.renderContainer(summaryContainer, containerWidth, b.String())
}

// renderLiveProbeDetails renders the hop-by-hop live view for a specific probe.
func (m *tuiModel) renderLiveProbeDetails(probeID uint16, maxHeight int) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	probe, exists := m.probes[probeID]
	if !exists {
		containerWidth := m.width - 4
		if m.noStyle {
			containerWidth = m.width
		}
		return m.renderContainer(borderStyle, containerWidth, "No data for probe")
	}

	var b strings.Builder

	srcPort := m.srcPort + m.selectedProbe
	focusLabel := ""
	if m.focus == focusDetails {
		focusLabel = " [detail focus]"
	}
	title := m.render(probeTitleStyle, fmt.Sprintf(" ► PROBE #%d ◄ - Source Port: %d%s ", probeID, srcPort, focusLabel))
	b.WriteString(title)
	b.WriteString("\n\n")

	contentWidth := m.width - 4
	if m.noStyle {
		contentWidth = m.width
	}
	contentWidth = max(contentWidth, 20)

	ttlWidth := 3
	lossWidth := 6
	sentWidth := 5
	statWidth := 7
	spaces := 8 // spaces between 9 columns
	fixedColumns := ttlWidth + lossWidth + sentWidth + (statWidth * 5) + spaces
	hostWidth := contentWidth - fixedColumns
	hostWidth = max(hostWidth, 10)

	headerFmt := fmt.Sprintf("%%-%ds %%-%ds %%%ds %%%ds %%%ds %%%ds %%%ds %%%ds %%%ds", ttlWidth, hostWidth, lossWidth, sentWidth, statWidth, statWidth, statWidth, statWidth, statWidth)
	header := fmt.Sprintf(headerFmt,
		"TTL", "Host", "Loss%", "Sent", "Last", "Avg", "Best", "Worst", "StDev")
	b.WriteString(m.render(headerStyle, truncateToWidth(header, contentWidth)))
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

		// Use hop-level Sent counter for immediate updates
		sent := hop.Sent
		lossPct := hop.LossPct

		lossStyle := statsGoodStyle
		if lossPct > 10 {
			lossStyle = statsWarningStyle
		}
		if lossPct > 25 {
			lossStyle = statsBadStyle
		}

		ipDisplay := truncateToWidth(formatHopDisplay(ip, ipStats.PTR, ipStats.ASN), hostWidth)

		cells := []string{
			formatCell(fmt.Sprintf("%d", ttl), ttlWidth, alignLeft),
			formatCell(ipDisplay, hostWidth, alignLeft),
			formatCell(fmt.Sprintf("%.1f%%", lossPct), lossWidth, alignRight),
			formatCell(fmt.Sprintf("%d", sent), sentWidth, alignRight),
			formatCell(fmt.Sprintf("%.2f", float64(ipStats.Last)/1000.0), statWidth, alignRight),
			formatCell(fmt.Sprintf("%.2f", float64(ipStats.Avg)/1000.0), statWidth, alignRight),
			formatCell(fmt.Sprintf("%.2f", float64(ipStats.Min)/1000.0), statWidth, alignRight),
			formatCell(fmt.Sprintf("%.2f", float64(ipStats.Max)/1000.0), statWidth, alignRight),
			formatCell(fmt.Sprintf("%.2f", ipStats.StdDev/1000.0), statWidth, alignRight),
		}

		if ip != "" && ip != "???" {
			cells[1] = m.render(ipStyle, cells[1])
		} else {
			cells[1] = m.render(ipStyle.Foreground(lipgloss.Color("#6B7280")), cells[1])
		}
		cells[2] = m.render(lossStyle, cells[2])

		line := strings.Join(cells, " ")
		line = truncateToWidth(line, contentWidth)
		bodyLines = append(bodyLines, m.render(hopStyle, line))

		if len(hop.IPs) > 1 {
			for altIP := range hop.IPs {
				if altIP == ip {
					continue
				}
				altStats := hop.IPs[altIP]
				if altStats == nil {
					continue
				}

				altValue := truncateToWidth("↳ "+formatHopDisplay(altIP, altStats.PTR, altStats.ASN), hostWidth)

				altLossStyle := statsGoodStyle
				if altStats.LossPct > 10 {
					altLossStyle = statsWarningStyle
				}
				if altStats.LossPct > 25 {
					altLossStyle = statsBadStyle
				}

				cells := []string{
					formatCell("", ttlWidth, alignLeft),
					formatCell(altValue, hostWidth, alignLeft),
					formatCell(fmt.Sprintf("%.1f%%", altStats.LossPct), lossWidth, alignRight),
					formatCell(fmt.Sprintf("%d", altStats.Responses+altStats.Lost), sentWidth, alignRight),
					formatCell(fmt.Sprintf("%.2f", float64(altStats.Last)/1000.0), statWidth, alignRight),
					formatCell(fmt.Sprintf("%.2f", float64(altStats.Avg)/1000.0), statWidth, alignRight),
					formatCell(fmt.Sprintf("%.2f", float64(altStats.Min)/1000.0), statWidth, alignRight),
					formatCell(fmt.Sprintf("%.2f", float64(altStats.Max)/1000.0), statWidth, alignRight),
					formatCell(fmt.Sprintf("%.2f", altStats.StdDev/1000.0), statWidth, alignRight),
				}

				cells[1] = m.render(ipStyle.Foreground(lipgloss.Color("#9CA3AF")), cells[1])
				cells[2] = m.render(altLossStyle, cells[2])

				line := strings.Join(cells, " ")
				line = truncateToWidth(line, contentWidth)
				bodyLines = append(bodyLines, m.render(hopStyle.Foreground(lipgloss.Color("#9CA3AF")), line))
			}
		}
	}

	visibleLines := maxHeight - 3
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

	containerWidth := m.width - 2
	if m.noStyle {
		containerWidth = m.width
	}
	return m.renderContainer(detailContainer, containerWidth, b.String())
}

// Helper types for aggregate stats
type probeAggregateStats struct {
	NumHops  int
	LossPct  float64
	AvgRTT   float64
	MinRTT   float64
	MaxRTT   float64
	StdDev   float64
	PathHash string // CRC32 or SHA256 hash of the path (truncated to 8 hex chars)
}

// calculateProbeAggregateStats calculates aggregate stats for a probe
func calculateProbeAggregateStats(probe *shared.ProbeStats, algorithm string) probeAggregateStats {
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
	stats.PathHash = shared.CalculatePathHashFromProbe(probe, algorithm)

	return stats
}

// waitForUpdate waits for the next update message
func waitForUpdate(updateCh chan tuiUpdateMsg) tea.Cmd {
	return func() tea.Msg {
		return <-updateCh
	}
}

// tickCmd returns a command that sends a tick message periodically
func tickCmd(interval time.Duration) tea.Cmd {
	if interval <= 0 {
		return nil
	}
	return tea.Tick(interval, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}
