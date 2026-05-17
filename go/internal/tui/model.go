package tui

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"reachability-scanner/engine"
)

// Messages sent from Engine -> Bubbletea
type resultMsg struct {
	result *engine.ScanResult
}
type progressMsg struct {
	done  int
	total int
}
type stateMsg struct {
	state string
}
type completeMsg struct {
	openCount  int
	deadCount  int
	totalCount int
}
type tickMsg time.Time

// bridge interface allowing Engine to talk to UI
type teaBridge struct {
	p *tea.Program
}

func (b *teaBridge) OnResult(r *engine.ScanResult) {
	b.p.Send(resultMsg{result: r})
}
func (b *teaBridge) OnProgress(done, total int) {
	b.p.Send(progressMsg{done: done, total: total})
}
func (b *teaBridge) OnStateChange(state string) {
	b.p.Send(stateMsg{state: state})
}
func (b *teaBridge) OnComplete(openCount, deadCount, totalCount int) {
	b.p.Send(completeMsg{openCount: openCount, deadCount: deadCount, totalCount: totalCount})
}

// ════════════════════════════════════════════════════════════════════════════════
// DNS Display Entry — used by the TUI to render the DNS Resolver Map
// ════════════════════════════════════════════════════════════════════════════════

// DnsDisplayEntry holds one row of the DNS Resolver Map table.
type DnsDisplayEntry struct {
	ResolverIP string
	Protocol   string
	IsPoisoned bool
	TTFB       int    // milliseconds
	AnswerIP   string // First answer IP from the response
	Answer     string // TXT answer or alternate DNS payload
	Error      string // Non-empty if the probe failed
}

// Model is the Bubbletea TUI state
type Model struct {
	engine   *engine.Engine
	keys     KeyMap
	progress progress.Model

	state     string
	done      int
	total     int
	openCount int
	deadCount int
	startTime time.Time
	width     int
	height    int

	// Standard HTTP mode — recent hits ring buffer
	recentHits [128]*engine.ScanResult
	hitIndex   int
	hitCount   int

	// DNS Discovery Mode state
	dnsMode       bool
	txtMode       bool
	dnsResults    [128]DnsDisplayEntry
	dnsIndex      int
	dnsEntryCount int
	dnsCleanCount int
	dnsPoisoned   int
	dnsHijacked   int

	help bool

	quitting bool
	finished bool
}

// NewModel initializes the TUI
func NewModel(cfg *engine.ScanConfig) *Model {
	prog := progress.New(progress.WithDefaultGradient())
	return &Model{
		keys:      DefaultKeyMap,
		progress:  prog,
		state:     "STARTING",
		startTime: time.Now(),
		dnsMode:   cfg.DnsDiscoveryMode,
		txtMode:   cfg.DnsTxtMode,
	}
}

// Run configures the engine, sets up the bridge, and starts the TUI
func (m *Model) Run(cfg *engine.ScanConfig) error {
	p := tea.NewProgram(m, tea.WithAltScreen())
	bridge := &teaBridge{p: p}
	m.engine = engine.NewEngine(cfg, bridge)

	go m.engine.Start()

	_, err := p.Run()
	return err
}

func (m *Model) Init() tea.Cmd {
	return tickCmd()
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*200, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.progress.Width = msg.Width - 10

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Quit):
			m.quitting = true
			return m, tea.Sequence(
				func() tea.Msg {
					m.engine.Stop()
					return nil
				},
			)
		case key.Matches(msg, m.keys.Pause):
			return m, func() tea.Msg {
				m.engine.Pause()
				return nil
			}
		case key.Matches(msg, m.keys.Resume):
			return m, func() tea.Msg {
				m.engine.Resume()
				return nil
			}
		case key.Matches(msg, m.keys.Help):
			m.help = !m.help
			return m, nil
		}

	case resultMsg:
		if m.dnsMode {
			m.handleDnsResult(msg.result)
		} else if m.txtMode {
			m.handleTxtResult(msg.result)
		} else {
			m.handleHttpResult(msg.result)
		}

	case progressMsg:
		m.done = msg.done
		m.total = msg.total

	case stateMsg:
		m.state = msg.state

	case completeMsg:
		m.finished = true
		m.quitting = true
		return m, tea.Quit

	case tickMsg:
		if m.quitting {
			return m, nil
		}
		return m, tickCmd()
	}

	return m, nil
}

// handleHttpResult processes a standard HTTP scan result.
func (m *Model) handleHttpResult(r *engine.ScanResult) {
	if r.Status > 0 {
		m.openCount++
		m.recentHits[m.hitIndex] = r
		m.hitIndex++
		if m.hitIndex >= 128 {
			m.hitIndex = 0
		}
		if m.hitCount < 128 {
			m.hitCount++
		}
	} else {
		m.deadCount++
	}
}

// handleDnsResult processes a DNS discovery result and populates the DNS map.
func (m *Model) handleDnsResult(r *engine.ScanResult) {
	if r.DnsProtocol == "" {
		return // Skip non-DNS results
	}

	if r.Status > 0 {
		m.openCount++
		if r.IsPoisoned {
			m.dnsPoisoned++
		} else {
			m.dnsCleanCount++
		}
		if isHijackedAnswer(r.ResolvedIP) {
			m.dnsHijacked++
		}
	} else {
		m.deadCount++
	}

	// Add to DNS display ring buffer
	answer := r.ResolvedIP
	if answer == "" {
		answer = r.DnsAnswer
	}
	entry := DnsDisplayEntry{
		ResolverIP: r.Label,
		Protocol:   r.DnsProtocol,
		IsPoisoned: r.IsPoisoned,
		TTFB:       r.LatencyMs,
		AnswerIP:   r.ResolvedIP,
		Answer:     answer,
		Error:      r.Error,
	}

	m.dnsResults[m.dnsIndex] = entry
	m.dnsIndex++
	if m.dnsIndex >= 128 {
		m.dnsIndex = 0
	}
	if m.dnsEntryCount < 128 {
		m.dnsEntryCount++
	}
}

func (m *Model) handleTxtResult(r *engine.ScanResult) {
	if r.DnsProtocol == "" {
		return
	}

	if r.Error == "" {
		m.openCount++
	} else {
		m.deadCount++
	}

	answer := r.DnsAnswer
	if answer == "" {
		answer = r.ResolvedIP
	}

	entry := DnsDisplayEntry{
		ResolverIP: r.Label,
		Protocol:   r.DnsProtocol,
		TTFB:       r.LatencyMs,
		AnswerIP:   r.ResolvedIP,
		Answer:     answer,
		Error:      r.Error,
	}

	m.dnsResults[m.dnsIndex] = entry
	m.dnsIndex++
	if m.dnsIndex >= 128 {
		m.dnsIndex = 0
	}
	if m.dnsEntryCount < 128 {
		m.dnsEntryCount++
	}
}

func (m *Model) View() string {
	if m.quitting && m.finished {
		if m.txtMode {
			return fmt.Sprintf("\n  TXT probe complete! Answered: %d, Failed: %d\n", m.openCount, m.deadCount)
		}
		if m.dnsMode {
			return fmt.Sprintf("\n  DNS Discovery complete! Clean: %d, Poisoned: %d, Hijacked: %d, Failed: %d\n",
				m.dnsCleanCount, m.dnsPoisoned, m.dnsHijacked, m.deadCount)
		}
		return fmt.Sprintf("\n  Scan complete! Open: %d, Dead: %d\n", m.openCount, m.deadCount)
	}
	if m.quitting {
		return "\n  Stopping and saving...\n"
	}

	frameWidth := m.width - 4
	if frameWidth <= 0 {
		frameWidth = 76
	}
	innerWidth := frameWidth - 4  // Border 2 + padding 2
	if innerWidth < 20 {
		innerWidth = maxInt(frameWidth-4, 10)
	}
	compact := m.height < 28 || frameWidth < 90

	accent := lipgloss.Color("#7bdff2")
	frameStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(accent).
		Padding(1, 1)
	sectionStyle := lipgloss.NewStyle().Padding(1, 0)
	divider := lipgloss.NewStyle().Foreground(lipgloss.Color("#a7f3d0")).Render(strings.Repeat("─", innerWidth))
	metricStyle := lipgloss.NewStyle().Padding(0, 1)
	metricLabel := lipgloss.NewStyle().Foreground(lipgloss.Color("#cbd5e1")).Bold(true)
	headerLine := titleStyle.Width(innerWidth).Render("WHITEDNS SCANNER")
	subtitle := dimStyle.Width(innerWidth).Align(lipgloss.Center).Render("Interactive network scanner — live resolver & endpoint insights")
	modeText := "HTTP SCAN"
	if m.dnsMode {
		modeText = "DNS DISCOVERY"
	} else if m.txtMode {
		modeText = "TXT RESOLVER PROBE"
	}
	modeBadge := pill(modeText, "#0b1020", "#7bdff2")
	modeLine := lipgloss.NewStyle().Width(innerWidth).Align(lipgloss.Center).Render(modeBadge)
	modeLabelText := "HTTP MODE ACTIVE"
	if m.dnsMode {
		modeLabelText = "DNS MODE ACTIVE"
	} else if m.txtMode {
		modeLabelText = "TXT MODE ACTIVE"
	}
	modeLabel := dimStyle.Width(innerWidth).Align(lipgloss.Center).Render(modeLabelText)
	controls := renderControls(innerWidth)

	progressPct := 0.0
	if m.total > 0 {
		progressPct = float64(m.done) / float64(m.total)
	}
	progressWidth := innerWidth - 24
	if progressWidth < 10 {
		progressWidth = maxInt(innerWidth-2, 10)
	}
	pctText := fmt.Sprintf("%d%%", int(progressPct*100))
	totalText := fmt.Sprintf("%d/%d", m.done, m.total)
	if m.total <= 0 {
		totalText = "streaming"
	}
	elapsed := time.Since(m.startTime).Round(time.Second)
	etaText := estimatedRemaining(m.done, m.total, time.Since(m.startTime))
	if m.total <= 0 {
		etaText = "streaming"
	}
	sectionContentWidth := innerWidth
	statsLineWidth := sectionContentWidth - 2
	if statsLineWidth < 24 {
		statsLineWidth = maxInt(sectionContentWidth-2, 24)
	}
	progressWidth = sectionContentWidth - 24
	if progressWidth < 10 {
		progressWidth = maxInt(sectionContentWidth-2, 10)
	}
	progressBar := renderProgressBar(progressWidth, progressPct)
	progressCard := sectionStyle.Width(sectionContentWidth).Render(
		lipgloss.JoinVertical(lipgloss.Left,
			dimStyle.Render("Progress"),
			progressBar,
			formatProgressStatsLine(statsLineWidth, pctText, totalText, elapsed.String(), etaText),
		),
	)

	metrics := sectionStyle.Width(innerWidth).Render(m.renderMetrics(innerWidth, metricStyle, metricLabel))
	activity := m.renderActivitySection(innerWidth, sectionStyle)
	footer := dimStyle.Width(innerWidth).Align(lipgloss.Right).Render("Developed by whisper the heaven & ashentajir")

	parts := []string{headerLine}
	if m.help {
		// Show a compact help card when help mode is toggled
		helpCard := m.renderHelp(innerWidth)
		parts = append(parts, helpCard)
		parts = append(parts, divider)
	} else {
		if !compact {
			parts = append(parts, subtitle)
		}
		parts = append(parts, modeLabel, modeLine, controls, divider, progressCard, divider, metrics, divider)
		if !compact || m.height > 22 {
			parts = append(parts, activity, divider)
		}
		parts = append(parts, footer)
	}

	content := lipgloss.JoinVertical(lipgloss.Left, parts...)

	return frameStyle.Width(frameWidth).Render(content) + "\n"
}

func renderControls(width int) string {
	// Render interactive key badges with short labels
	badge := func(k, label string) string {
		return pill(k, "#0b1020", "#7bdff2") + " " + dimStyle.Render(label)
	}

	helpBadge := pill("H", "#0b1020", "#ffe066") + " " + dimStyle.Render("Help")

	left := badge("P", "Pause") + "  " + badge("R", "Resume") + "  " + badge("Q", "Quit")
	if width < 62 {
		// Compact layout
		left = badge("P", "P") + " " + badge("R", "R") + " " + badge("Q", "Q")
	}
	right := helpBadge
	// Center combined controls
	combined := lipgloss.JoinHorizontal(lipgloss.Center, left, lipgloss.NewStyle().Width(4).Render(""), right)
	return dimStyle.Width(width).Align(lipgloss.Center).Render(combined)
}

func (m *Model) renderMetrics(width int, metricStyle lipgloss.Style, labelStyle lipgloss.Style) string {
	type metricSpec struct {
		title string
		value string
		color lipgloss.Style
	}

	var specs []metricSpec
	if m.dnsMode {
		specs = []metricSpec{
			{"Scanned", fmt.Sprintf("%d", m.done), deepPurple},
			{"Clean", fmt.Sprintf("%d", m.dnsCleanCount), greenText},
			{"Poisoned", fmt.Sprintf("%d", m.dnsPoisoned), magentaText},
			{"Hijacked", fmt.Sprintf("%d", m.dnsHijacked), yellowText},
			{"Failed", fmt.Sprintf("%d", m.deadCount), redText},
		}
	} else if m.txtMode {
		specs = []metricSpec{
			{"Scanned", fmt.Sprintf("%d", m.done), deepPurple},
			{"Answered", fmt.Sprintf("%d", m.openCount), greenText},
			{"Failed", fmt.Sprintf("%d", m.deadCount), redText},
			{"Records", fmt.Sprintf("%d", m.dnsEntryCount), cyanText},
		}
	} else {
		specs = []metricSpec{
			{"Scanned", fmt.Sprintf("%d", m.done), deepPurple},
			{"Reachable", fmt.Sprintf("%d", m.openCount), greenText},
			{"Failed", fmt.Sprintf("%d", m.deadCount), redText},
			{"Alerts", fmt.Sprintf("%d", m.dnsPoisoned+m.dnsHijacked), magentaText},
		}
	}

	count := len(specs)
	if count == 0 {
		return ""
	}

	baseWidth := width / count
	remainder := width % count
	cards := make([]string, 0, count)
	for i, spec := range specs {
		totalWidth := baseWidth
		if i < remainder {
			totalWidth++
		}
		innerWidth := totalWidth - 2
		if innerWidth < 0 {
			innerWidth = 0
		}
		cards = append(cards, metricCard(spec.title, spec.value, spec.color, innerWidth, metricStyle, labelStyle))
	}

	return lipgloss.JoinHorizontal(lipgloss.Top, cards...)
}

func metricCard(title, value string, valueColor lipgloss.Style, width int, baseStyle lipgloss.Style, labelStyle lipgloss.Style) string {
	line := lipgloss.JoinHorizontal(
		lipgloss.Top,
		labelStyle.Render(title),
		lipgloss.NewStyle().Width(1).Render(" "),
		valueColor.Bold(true).Render(value),
	)
	return baseStyle.Width(width).Render(line)
}

func (m *Model) renderActivitySection(width int, sectionStyle lipgloss.Style) string {
	if m.dnsMode {
		entries := m.latestDNSEntries(m.activityLimit())
		rows := make([]string, 0, len(entries))
		for _, entry := range entries {
			rows = append(rows, renderDNSEntryCompact(entry, width-4))
		}
		body := renderListBody(rows, width)
		return sectionStyle.Width(width).Render(dimStyle.Render("DNS activity") + "\n" + body)
	}
	if m.txtMode {
		entries := m.latestDNSEntries(m.activityLimit())
		rows := make([]string, 0, len(entries))
		for _, entry := range entries {
			rows = append(rows, renderDNSEntryCompact(entry, width-4))
		}
		body := renderListBody(rows, width)
		return sectionStyle.Width(width).Render(dimStyle.Render("TXT activity") + "\n" + body)
	}

	hits := m.latestHTTPHits(m.activityLimit())
	rows := make([]string, 0, len(hits))
	for _, hit := range hits {
		rows = append(rows, renderHTTPHitCompact(hit, width-4))
	}
	body := renderListBody(rows, width)
	return sectionStyle.Width(width).Render(dimStyle.Render("Recent active nodes") + "\n" + body)
}

func renderListBody(rows []string, width int) string {
	if len(rows) == 0 {
		return dimStyle.Render("Waiting for results...")
	}
	// Ensure consistent separators and bounded height to avoid UI jumps.
	maxRows := len(rows)
	if maxRows > 6 {
		maxRows = 6
	}
	trimmed := rows
	if len(rows) > maxRows {
		trimmed = rows[:maxRows]
	}
	separator := dimStyle.Render(strings.Repeat("─", maxInt(width-6, 10)))
	parts := make([]string, 0, len(trimmed)*2-1)
	for i, row := range trimmed {
		if i > 0 {
			parts = append(parts, separator)
		}
		parts = append(parts, row)
	}
	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

func (m *Model) renderHelp(width int) string {
	lines := []string{
		pill("P", "#0b1020", "#7bdff2") + "  " + dimStyle.Render("Pause scanning"),
		pill("R", "#0b1020", "#7bdff2") + "  " + dimStyle.Render("Resume scanning"),
		pill("Q", "#ffffff", "#ff6b6b") + "  " + dimStyle.Render("Quit & save results"),
		pill("H", "#0b1020", "#ffe066") + "  " + dimStyle.Render("Toggle this help"),
	}
	body := strings.Join(lines, "\n")
	return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1, 1).Width(width).Render(body)
}

func renderHTTPHit(hit *engine.ScanResult, width int) string {
	labelWidth := maxInt(16, width/3)
	urlWidth := maxInt(24, width-8)
	status := statusPill(hit.Status)
	label := whiteBoldStyle().Render(truncateText(hit.Label, labelWidth))
	url := dimStyle.Render(truncateText(hit.URL, urlWidth))
	ip := hit.ResolvedIP
	if ip == "" {
		ip = "-"
	}
	meta := dimStyle.Render(fmt.Sprintf("%s:%d", ip, hit.Port)) + "  " + latencyPill(hit.LatencyMs)

	cardStyle := lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("#4b2a7a")).Padding(0, 0)
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		lipgloss.JoinHorizontal(lipgloss.Top, label, status),
		url,
		meta,
	)
	return cardStyle.Width(width).Render(content)
}

func renderHTTPHitCompact(hit *engine.ScanResult, width int) string {
	if width < 40 {
		width = 40
	}
	labelWidth := maxInt(12, width/5)
	statusWidth := 9
	latWidth := 7
	ipWidth := 20
	sep := " | "
	sepTotal := 4 * len(sep)
	urlWidth := width - (labelWidth + statusWidth + latWidth + ipWidth + sepTotal)
	if urlWidth < 10 {
		urlWidth = 10
	}

	statusText := fmt.Sprintf("HTTP %d", hit.Status)
	if hit.Status <= 0 {
		statusText = "HTTP ERR"
	}
	label := padRightPlain(truncateText(hit.Label, labelWidth), labelWidth)
	status := padRightPlain(truncateText(statusText, statusWidth), statusWidth)
	lat := padRightPlain(truncateText(fmt.Sprintf("%dms", hit.LatencyMs), latWidth), latWidth)
	ip := hit.ResolvedIP
	if ip == "" {
		ip = "-"
	}
	ipPort := padRightPlain(truncateText(fmt.Sprintf("%s:%d", ip, hit.Port), ipWidth), ipWidth)
	url := padRightPlain(truncateText(hit.URL, urlWidth), urlWidth)

	return label + sep + status + sep + lat + sep + ipPort + sep + url
}

func renderDNSEntry(entry DnsDisplayEntry, width int) string {
	resolver := whiteBoldStyle().Render(truncateText(entry.ResolverIP, maxInt(16, width/3)))
	protocol := protocolPill(entry.Protocol)
	integrity := dnsIntegrityPill(entry)
	stateBadge := dnsStateBadge(entry)
	answer := dnsDisplayAnswer(entry)
	if answer == "" {
		answer = entry.Error
	}
	if answer == "" {
		answer = "<no-answer>"
	}
	answerLine := dimStyle.Render(truncateText(answer, maxInt(24, width-8)))

	cardStyle := lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("#4b2a7a")).Padding(0, 0)
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		lipgloss.JoinHorizontal(lipgloss.Top, resolver, protocol, integrity, stateBadge),
		answerLine,
		latencyPill(entry.TTFB),
	)
	return cardStyle.Width(width).Render(content)
}

func renderDNSEntryCompact(entry DnsDisplayEntry, width int) string {
	if width < 40 {
		width = 40
	}
	resolverWidth := maxInt(16, width/5)
	protoWidth := 8
	stateWidth := 8
	latWidth := 7
	sep := " | "
	sepTotal := 4 * len(sep)
	answerWidth := width - (resolverWidth + protoWidth + stateWidth + latWidth + sepTotal)
	if answerWidth < 10 {
		answerWidth = 10
	}

	resolver := padRightPlain(truncateText(entry.ResolverIP, resolverWidth), resolverWidth)
	proto := padRightPlain(truncateText(entry.Protocol, protoWidth), protoWidth)
	state := padRightPlain(truncateText(dnsStateText(entry), stateWidth), stateWidth)
	lat := padRightPlain(truncateText(fmt.Sprintf("%dms", entry.TTFB), latWidth), latWidth)
	answer := dnsDisplayAnswer(entry)
	if answer == "" {
		answer = entry.Error
	}
	if answer == "" {
		answer = "<no-answer>"
	}
	answer = padRightPlain(truncateText(answer, answerWidth), answerWidth)

	return resolver + sep + proto + sep + state + sep + lat + sep + answer
}

func formatProgressStatsLine(width int, pctText, totalText, elapsedText, etaText string) string {
	left := fmt.Sprintf("%s   %s   %s", pctText, totalText, elapsedText)
	right := fmt.Sprintf("ETA %s", etaText)
	if width < len(left)+len(right)+1 {
		return dimStyle.Render(left + "   " + right)
	}
	spaces := width - len(left) - len(right)
	return dimStyle.Render(left + strings.Repeat(" ", spaces) + right)
}

func (m *Model) latestHTTPHits(limit int) []*engine.ScanResult {
	if limit < 1 {
		limit = 1
	}
	result := make([]*engine.ScanResult, 0, limit)
	for i := 0; i < m.hitCount && len(result) < limit; i++ {
		idx := (m.hitIndex - 1 - i + 128) % 128
		hit := m.recentHits[idx]
		if hit != nil {
			result = append(result, hit)
		}
	}
	return result
}

func (m *Model) latestDNSEntries(limit int) []DnsDisplayEntry {
	if limit < 1 {
		limit = 1
	}
	result := make([]DnsDisplayEntry, 0, limit)
	seen := make(map[string]struct{})
	for i := 0; i < m.dnsEntryCount && len(result) < limit; i++ {
		idx := (m.dnsIndex - 1 - i + 128) % 128
		entry := m.dnsResults[idx]
		if entry.ResolverIP == "" {
			continue
		}
		key := entry.ResolverIP + "|" + entry.Protocol
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, entry)
	}
	return result
}

func dnsDisplayAnswer(entry DnsDisplayEntry) string {
	if entry.Answer != "" {
		return entry.Answer
	}
	return entry.AnswerIP
}

func (m *Model) activityLimit() int {
	if m.dnsMode {
		return 2
	}
	if m.height < 20 {
		return 2
	}
	if m.height < 26 {
		return 3
	}
	if m.height < 34 {
		return 4
	}
	if m.height < 44 {
		return 5
	}
	return 6
}

func isHijackedAnswer(answerIP string) bool {
	ip := net.ParseIP(answerIP)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified()
}

func renderProgressBar(width int, pct float64) string {
	if width < 12 {
		width = 12
	}
	if pct < 0 {
		pct = 0
	}
	if pct > 1 {
		pct = 1
	}
	filled := int(float64(width) * pct)
	if filled > width {
		filled = width
	}
	filledPart := deepPurple.Render(strings.Repeat("█", filled))
	emptyPart := dimStyle.Render(strings.Repeat("░", width-filled))
	return filledPart + emptyPart
}

func estimatedRemaining(done, total int, elapsed time.Duration) string {
	if total <= 0 || done <= 0 || done >= total {
		return "--:--"
	}

	remaining := time.Duration(int64(elapsed) * int64(total-done) / int64(done))
	if remaining < 0 {
		remaining = 0
	}
	if remaining < time.Minute {
		return remaining.Round(time.Second).String()
	}

	hours := int(remaining / time.Hour)
	remaining -= time.Duration(hours) * time.Hour
	minutes := int(remaining / time.Minute)
	remaining -= time.Duration(minutes) * time.Minute
	seconds := int(remaining / time.Second)
	if hours > 0 {
		return fmt.Sprintf("%dh %02dm %02ds", hours, minutes, seconds)
	}
	return fmt.Sprintf("%dm %02ds", minutes, seconds)
}

func statusPill(status int) string {
	label := fmt.Sprintf("HTTP %d", status)
	if status < 300 {
		return pill(label, "#ffffff", "#1f7a44")
	}
	if status < 400 {
		return pill(label, "#ffffff", "#1f6f8a")
	}
	if status < 500 {
		return pill(label, "#ffffff", "#9b7a1f")
	}
	return pill(label, "#ffffff", "#8a2640")
}

func latencyPill(latency int) string {
	return pill(latencyText(latency), "#ffffff", "#3c255e")
}

func latencyText(latency int) string {
	return fmt.Sprintf("%dms", latency)
}

func protocolPill(proto string) string {
	label := strings.ToUpper(proto)
	switch label {
	case "UDP":
		return pill(label, "#ffffff", "#9b30ff")
	case "TCP":
		return pill(label, "#ffffff", "#1f6f8a")
	case "DOT":
		return pill("DoT", "#ffffff", "#1f7a44")
	case "DOH":
		return pill("DoH", "#ffffff", "#9b7a1f")
	default:
		return pill(label, "#ffffff", "#3c255e")
	}
}

func dnsIntegrityPill(entry DnsDisplayEntry) string {
	if entry.Error != "" && entry.AnswerIP == "" {
		return pill("FAIL", "#ffffff", "#8a2640")
	}
	if entry.IsPoisoned {
		return pill("POISONED", "#ffffff", "#9b30ff")
	}
	if entry.AnswerIP != "" {
		if ip := net.ParseIP(entry.AnswerIP); ip != nil {
			if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
				return pill("HIJACK", "#ffffff", "#9b7a1f")
			}
		}
	}
	return pill("CLEAN", "#ffffff", "#1f7a44")
}

func dnsStateBadge(entry DnsDisplayEntry) string {
	if entry.Error != "" && entry.AnswerIP == "" {
		return pill("FAIL", "#ffffff", "#8a2640")
	}
	if entry.IsPoisoned {
		return pill("POISON", "#ffffff", "#9b30ff")
	}
	if entry.AnswerIP != "" {
		if ip := net.ParseIP(entry.AnswerIP); ip != nil {
			if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
				return pill("HIJACK", "#ffffff", "#9b7a1f")
			}
		}
	}
	return pill("CLEAN", "#ffffff", "#1f7a44")
}

func dnsStateText(entry DnsDisplayEntry) string {
	if entry.Error != "" && entry.AnswerIP == "" {
		return "FAIL"
	}
	if entry.IsPoisoned {
		return "POISON"
	}
	if entry.AnswerIP != "" {
		if ip := net.ParseIP(entry.AnswerIP); ip != nil {
			if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
				return "HIJACK"
			}
		}
	}
	return "CLEAN"
}

func pill(text, fg, bg string) string {
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color(fg)).
		Background(lipgloss.Color(bg)).
		Padding(0, 1).
		Bold(true).
		Render(text)
}

func truncateText(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	if limit == 1 {
		return "…"
	}
	return string(runes[:limit-1]) + "…"
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func padRightPlain(s string, width int) string {
	if width <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) >= width {
		return string(r[:width])
	}
	return string(r) + strings.Repeat(" ", width-len(r))
}

func whiteBoldStyle() lipgloss.Style {
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF"))
}
