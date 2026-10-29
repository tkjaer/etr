package output

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/tkjaer/etr/pkg/etr"
)

// newReplyTestTUI returns an 80x40 unstyled TUI with one probe whose hops
// are given as TTL -> IP stats.
func newReplyTestTUI(t *testing.T, hops map[uint8]map[string]*etr.HopIPStats) *tuiModel {
	t.Helper()
	tui := NewBubbleTUIOutput(Info{
		Destination: "192.0.2.50", Protocol: "TCP", SrcPort: 50000, DstPort: 80,
		ParallelProbes: 1, NoStyle: true,
	})
	m := tui.model
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 40})
	for ttl, ips := range hops {
		var current string
		for ip := range ips {
			current = ip
		}
		tui.UpdateHop(0, ttl, etr.HopStats{IPs: ips, CurrentIP: current, Sent: 1, Received: 1})
	}
	return m
}

// hopLine returns the first line of the view whose TTL column starts with ttl.
func hopLine(view, ttl string) string {
	for line := range strings.SplitSeq(view, "\n") {
		if strings.HasPrefix(line, ttl+" ") {
			return line
		}
	}
	return ""
}

func checkWidth(t *testing.T, view string, width int) {
	t.Helper()
	for line := range strings.SplitSeq(view, "\n") {
		if w := lipgloss.Width(line); w > width {
			t.Errorf("line is %d wide, want <= %d: %q", w, width, line)
		}
	}
}

func TestTUIMarksForwardedDestination(t *testing.T) {
	m := newReplyTestTUI(t, map[uint8]map[string]*etr.HopIPStats{
		5: {"198.51.100.1": {Responses: 1, Reply: etr.ReplyTimeExceeded}},
		6: {"192.0.2.50": {Responses: 1, Reply: etr.ReplyTimeExceeded, Forwarded: true}},
		7: {"192.0.2.50": {Responses: 1, Reply: etr.ReplySYNACK}},
	})

	view := m.View()
	checkWidth(t, view, 80)
	if hopLine(view, "6*") == "" {
		t.Errorf("TTL 6 isn't marked as forwarded:\n%s", view)
	}
	if hopLine(view, "5*") != "" || hopLine(view, "7*") != "" {
		t.Errorf("a hop other than TTL 6 is marked as forwarded:\n%s", view)
	}
	if !strings.Contains(view, "* destination forwards port 80") {
		t.Errorf("view is missing the forwarded caption:\n%s", view)
	}
}

func TestTUIReplyColumnToggle(t *testing.T) {
	m := newReplyTestTUI(t, map[uint8]map[string]*etr.HopIPStats{
		6: {"192.0.2.50": {Responses: 1, Reply: etr.ReplyTimeExceeded, Forwarded: true}},
		7: {"192.0.2.50": {Responses: 1, Reply: etr.ReplySYNACK}},
	})
	toggle := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}}

	if view := m.View(); !strings.Contains(view, "StDev") || strings.Contains(view, "Reply ") {
		t.Errorf("reply column shown before toggling:\n%s", view)
	}

	m.Update(toggle)
	view := m.View()
	checkWidth(t, view, 80)
	if strings.Contains(view, "StDev") {
		t.Errorf("StDev still shown with the reply column on:\n%s", view)
	}
	if !strings.Contains(view, "r reply types") {
		t.Errorf("help bar doesn't list the reply toggle:\n%s", view)
	}
	if !strings.HasSuffix(hopLine(view, "6*"), "TTL exc") || !strings.HasSuffix(hopLine(view, "7"), "SYN-ACK") {
		t.Errorf("reply column doesn't show the reply types:\n%s", view)
	}

	m.Update(toggle)
	if view := m.View(); !strings.Contains(view, "StDev") {
		t.Errorf("StDev not back after toggling off:\n%s", view)
	}
}

func TestTUINoForwardedNoteWithoutForwarding(t *testing.T) {
	m := newReplyTestTUI(t, map[uint8]map[string]*etr.HopIPStats{
		5: {"198.51.100.1": {Responses: 1, Reply: etr.ReplyTimeExceeded}},
		6: {"192.0.2.50": {Responses: 1, Reply: etr.ReplySYNACK}},
	})

	view := m.View()
	if strings.Contains(view, "destination forwards") || strings.Contains(view, "*") {
		t.Errorf("forwarded marker or note shown without forwarding:\n%s", view)
	}
}

func TestTUIForwardedCaptionInBorder(t *testing.T) {
	m := newReplyTestTUI(t, map[uint8]map[string]*etr.HopIPStats{
		6: {"192.0.2.50": {Responses: 1, Reply: etr.ReplyTimeExceeded, Forwarded: true}},
		7: {"192.0.2.50": {Responses: 1, Reply: etr.ReplySYNACK}},
	})
	m.noStyle = false

	lines := strings.Split(m.View(), "\n")
	var top, bottom string
	for _, line := range lines {
		if strings.HasPrefix(line, "╭") {
			top = line
		}
		if strings.Contains(line, "destination forwards port 80") {
			bottom = line
		}
	}
	if !strings.HasPrefix(bottom, "╰─ * destination forwards port 80") || !strings.HasSuffix(bottom, "─╯") {
		t.Errorf("caption isn't drawn in the bottom border: %q", bottom)
	}
	if lipgloss.Width(bottom) != lipgloss.Width(top) {
		t.Errorf("bottom border is %d wide, top is %d", lipgloss.Width(bottom), lipgloss.Width(top))
	}
}

func TestTUIFillsTerminal(t *testing.T) {
	for _, probes := range []uint16{1, 10} {
		for _, hops := range []uint8{3, 20} {
			for _, height := range []int{16, 24, 40} {
				for _, fullHelp := range []bool{false, true} {
					tui := NewBubbleTUIOutput(Info{
						Destination: "192.0.2.50", Protocol: "TCP", SrcPort: 50000, DstPort: 80,
						ParallelProbes: probes,
					})
					m := tui.model
					for ttl := uint8(1); ttl <= hops; ttl++ {
						tui.UpdateHop(0, ttl, etr.HopStats{
							IPs:       map[string]*etr.HopIPStats{"198.51.100.1": {Responses: 1}},
							CurrentIP: "198.51.100.1",
						})
					}
					m.Update(tea.WindowSizeMsg{Width: 80, Height: height})
					m.help.ShowAll = fullHelp
					if n := len(strings.Split(m.View(), "\n")); n != height {
						t.Errorf("%d probes, %d hops, height %d, full help %v: view has %d lines, want %d",
							probes, hops, height, fullHelp, n, height)
					}
				}
			}
		}
	}
}
