package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/its0din-ai/tldr/internal/buildinfo"
	"github.com/its0din-ai/tldr/internal/scanner"
)

type eventMsg scanner.Event
type eventClosedMsg struct{}
type tickMsg time.Time

type logLine struct {
	level scanner.LogLevel
	text  string
}

type priceLine struct {
	tld    string
	price  *scanner.Price
	err    string
	cached bool
}

type Model struct {
	cancel context.CancelFunc
	events <-chan scanner.Event

	width, height int
	started       time.Time
	phase         scanner.Phase
	plan          *scanner.Plan
	progress      scanner.Progress
	checks        []scanner.CheckResult
	checkDone     int
	checkTotal    int
	preflight     *scanner.PreflightSummary
	found         []scanner.Result
	logs          []logLine
	prices        []priceLine
	priceDone     int
	priceTotal    int
	summary       *scanner.Summary
	err           error
	spinner       int
	finished      bool
	closed        bool
}

func New(cancel context.CancelFunc, events <-chan scanner.Event) Model {
	return Model{
		cancel:  cancel,
		events:  events,
		started: time.Now(),
		phase:   scanner.PhaseLoading,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(waitForEvent(m.events), tickCmd())
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		m.spinner++
		return m, tickCmd()

	case eventMsg:
		m.apply(scanner.Event(msg))
		return m, waitForEvent(m.events)

	case eventClosedMsg:
		m.closed = true
		if !m.finished {
			m.phase = scanner.PhaseDone
		}
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		case "enter":
			if m.finished {
				if m.cancel != nil {
					m.cancel()
				}
				return m, tea.Quit
			}
		}
	}
	return m, nil
}

func (m *Model) apply(event scanner.Event) {
	switch event.Type {
	case scanner.EventPlan:
		if event.Plan != nil {
			m.plan = event.Plan
			if m.progress.Limit == 0 {
				m.progress.Limit = event.Plan.Limit
				m.progress.MaxChecks = event.Plan.MaxChecks
			}
		}
	case scanner.EventPhase:
		m.phase = event.Phase
	case scanner.EventLog:
		m.logs = append(m.logs, logLine{level: event.Level, text: event.Message})
		if len(m.logs) > 100 {
			m.logs = m.logs[len(m.logs)-100:]
		}
	case scanner.EventPreflightPlan:
		m.checkTotal = event.CheckTotal
		m.checkDone = 0
		m.checks = nil
	case scanner.EventPreflightCheck:
		if event.Check != nil {
			m.checks = append(m.checks, *event.Check)
			if len(m.checks) > 100 {
				m.checks = m.checks[len(m.checks)-100:]
			}
			m.checkDone = event.CheckDone
		}
	case scanner.EventPreflightDone:
		m.preflight = event.Preflight
	case scanner.EventProgress:
		m.progress = event.Progress
	case scanner.EventFound:
		m.found = append(m.found, event.Result)
	case scanner.EventPricing:
		m.priceDone = event.Pricing.Done
		m.priceTotal = event.Pricing.Total
		if event.Pricing.TLD != "" ||
			event.Pricing.Price != nil || event.Pricing.Err != "" {
			m.prices = append(m.prices, priceLine{
				tld: event.Pricing.TLD, price: event.Pricing.Price,
				err: event.Pricing.Err, cached: event.Pricing.Cached,
			})
			if len(m.prices) > 100 {
				m.prices = m.prices[len(m.prices)-100:]
			}
		}
	case scanner.EventDone:
		m.summary = event.Summary
		m.phase = scanner.PhaseDone
		m.finished = true
	case scanner.EventError:
		m.err = event.Err
		m.phase = scanner.PhaseError
		m.finished = true
	}
}

func waitForEvent(ch <-chan scanner.Event) tea.Cmd {
	return func() tea.Msg {
		event, ok := <-ch
		if !ok {
			return eventClosedMsg{}
		}
		return eventMsg(event)
	}
}

func tickCmd() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	dimStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	okStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	warnStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	failStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	infoStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("81"))
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func (m Model) View() string {
	width := m.width
	if width <= 0 {
		width = 100
	}

	var lines []string
	lines = append(lines, m.header(width))
	lines = append(lines, m.planLine())

	switch m.phase {
	case scanner.PhaseLoading:
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("%s Loading IANA TLD/RDAP bootstrap data ...",
			m.spinnerFrame()))
		lines = append(lines, dimStyle.Render(fmt.Sprintf(
			"   elapsed %s · %s", scanner.FormatDuration(time.Since(m.started)),
			m.proxyLabel())))
	case scanner.PhasePreflight:
		lines = append(lines, m.preflightView()...)
	case scanner.PhaseScanning, scanner.PhaseSearching:
		lines = append(lines, m.scanningView(width)...)
	case scanner.PhasePricing:
		lines = append(lines, m.pricingView(width)...)
	case scanner.PhaseDone, scanner.PhaseError:
		lines = append(lines, m.doneView(width)...)
	}

	footer := m.footer()
	limit := m.height - 2
	if limit > 0 && len(lines) > limit {
		lines = lines[:limit]
	}
	lines = append(lines, footer)

	for i := range lines {
		lines[i] = lipgloss.NewStyle().MaxWidth(width).Render(lines[i])
	}
	return strings.Join(lines, "\n")
}

func (m Model) header(width int) string {
	title := titleStyle.Render("tldr-scanner " + buildinfo.Version)
	right := phaseStyle(m.phase).Render(phaseLabel(m.phase))
	if !m.finished {
		right += " " + infoStyle.Render(m.spinnerFrame())
	}
	gap := width - lipgloss.Width(title) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	return title + strings.Repeat(" ", gap) + right
}

func (m Model) planLine() string {
	if m.plan == nil {
		return dimStyle.Render("Loading configuration ...")
	}
	plan := m.plan
	http := "direct"
	if plan.ProxyCount > 0 {
		http = fmt.Sprintf("%d proxies", plan.ProxyCount)
	}
	if plan.Mode == "search" {
		scope := fmt.Sprintf("TLDs ≤ %d chars", plan.MaxTLDLen)
		if plan.TLDsExplicit {
			scope = "selected TLDs"
		}
		return dimStyle.Render(fmt.Sprintf(
			"Search %s · %s · %s targets · %s · seed %d",
			plan.SearchLabel, scope,
			formatInt(int64(plan.SearchTotal)), http, plan.Seed))
	}
	extra := ""
	if plan.Sequential != "" {
		extra = " · seq " + plan.Sequential
	}
	return dimStyle.Render(fmt.Sprintf(
		"TLDs %s (%s RDAP / %s WHOIS) · length %d..%d · limit %d%s · %s · seed %d",
		formatInt(int64(plan.TLDCount)), formatInt(int64(plan.RDAPCount)),
		formatInt(int64(plan.WHOISCount)), plan.MinLength, plan.MaxLength,
		plan.Limit, extra, http, plan.Seed))
}

func (m Model) preflightView() []string {
	lines := []string{""}
	lines = append(lines, infoStyle.Render("Connectivity checks")+
		dimStyle.Render(" — distinct from scanning; network latency here is expected."))
	lines = append(lines, fmt.Sprintf("%-36s %s · %s %s",
		bar(m.checkDone, m.checkTotal, 28),
		fmt.Sprintf("%d/%d", m.checkDone, m.checkTotal),
		scanner.FormatDuration(time.Since(m.started)),
		m.spinnerFrame()))
	if m.preflight != nil {
		lines = append(lines, fmt.Sprintf("  %s %d ok · %s %d warn · %s %d failed · %d skipped",
			statusStyle(scanner.CheckOK).Render("✓"), m.preflight.OK,
			statusStyle(scanner.CheckWarn).Render("!"), m.preflight.Warn,
			statusStyle(scanner.CheckFail).Render("✗"), m.preflight.Fail,
			m.preflight.Skip))
	}
	lines = append(lines, "")
	lines = append(lines, dimStyle.Render("Recent endpoints"))
	start := len(m.checks) - 8
	if start < 0 {
		start = 0
	}
	for _, check := range m.checks[start:] {
		lines = append(lines, "  "+renderCheck(check))
	}
	if failures := recentFailures(m.checks, 4); len(failures) > 0 {
		lines = append(lines, "", failStyle.Render("Failures / warnings"))
		for _, check := range failures {
			lines = append(lines, "  "+renderCheck(check))
		}
		if m.preflight != nil {
			hidden := m.preflight.Fail + m.preflight.Warn - len(failures)
			if hidden > 0 {
				lines = append(lines, dimStyle.Render(fmt.Sprintf(
					"  ... and %d more (see -no-tui output for the full list)", hidden)))
			}
		}
	}
	return lines
}

func (m Model) scanningView(width int) []string {
	if m.plan != nil && m.plan.Mode == "search" {
		return m.searchView(width)
	}
	progress := m.progress
	found := int64(len(m.found))
	lines := []string{""}
	lines = append(lines, fmt.Sprintf("Found %s / %d  %s",
		formatInt(found), progress.Limit, bar(int(found), progress.Limit, 24)))
	if progress.Level == 0 {
		lines = append(lines, dimStyle.Render(
			"  preparing candidate stream ..."))
	} else {
		lines = append(lines, fmt.Sprintf(
			"  length %d · checked %s / %s max · %.1f/s · active %s · elapsed %s",
			progress.Level, formatInt(progress.Checked), formatInt(int64(progress.MaxChecks)),
			progress.Rate, formatInt(progress.Active),
			scanner.FormatDuration(progress.Elapsed)))
	}
	lines = append(lines, dimStyle.Render(fmt.Sprintf(
		"  taken %s · unknown %s · canceled %s · cache %s",
		formatInt(progress.Taken), formatInt(progress.Unknown),
		formatInt(progress.Canceled), formatInt(progress.CacheHits))))

	if progress.Rate < 0.1 && progress.Active > 0 {
		lines = append(lines, warnStyle.Render(fmt.Sprintf(
			"  waiting on %s network request(s) — endpoint latency, not a stalled scan",
			formatInt(progress.Active))))
	} else if progress.Rate == 0 && progress.Active == 0 {
		lines = append(lines, dimStyle.Render("  preparing next candidates ..."))
	}

	if m.preflight != nil {
		lines = append(lines, dimStyle.Render(fmt.Sprintf(
			"  connectivity: %d ok · %d warn · %d failed",
			m.preflight.OK, m.preflight.Warn, m.preflight.Fail)))
	}

	if len(m.found) > 0 {
		lines = append(lines, "", dimStyle.Render("Found"))
		start := len(m.found) - 10
		if start < 0 {
			start = 0
		}
		for _, result := range m.found[start:] {
			note := ""
			if result.Cached {
				note += dimStyle.Render(" (cached)")
			}
			if result.Method == "dns" {
				note += dimStyle.Render(" (DNS only, unverified)")
			}
			lines = append(lines, fmt.Sprintf("  + %-22s [%s]%s",
				result.Domain, result.Method, note))
		}
	}

	if len(m.logs) > 0 {
		lines = append(lines, "", dimStyle.Render("Activity"))
		start := len(m.logs) - 5
		if start < 0 {
			start = 0
		}
		for _, line := range m.logs[start:] {
			lines = append(lines, "  "+logStyle(line.level).Render(line.text))
		}
	}
	return lines
}

func (m Model) searchView(width int) []string {
	progress := m.progress
	total := 0
	if m.plan != nil {
		total = m.plan.SearchTotal
	}
	available := int64(len(m.found))
	lines := []string{""}
	lines = append(lines, fmt.Sprintf("Available %d  %s",
		available, bar(int(progress.Checked), total, 24)))
	lines = append(lines, fmt.Sprintf(
		"  checked %s / %d TLDs · %.1f/s · active %s · elapsed %s",
		formatInt(progress.Checked), total, progress.Rate,
		formatInt(progress.Active),
		scanner.FormatDuration(progress.Elapsed)))
	lines = append(lines, dimStyle.Render(fmt.Sprintf(
		"  taken %s · unknown %s · canceled %s · cache %s",
		formatInt(progress.Taken), formatInt(progress.Unknown),
		formatInt(progress.Canceled), formatInt(progress.CacheHits))))

	if progress.Rate < 0.1 && progress.Active > 0 {
		lines = append(lines, warnStyle.Render(fmt.Sprintf(
			"  waiting on %s network request(s) — endpoint latency, not a stalled scan",
			formatInt(progress.Active))))
	} else if progress.Rate == 0 && progress.Active == 0 {
		lines = append(lines, dimStyle.Render("  preparing targets ..."))
	}
	if m.preflight != nil {
		lines = append(lines, dimStyle.Render(fmt.Sprintf(
			"  connectivity: %d ok · %d warn · %d failed",
			m.preflight.OK, m.preflight.Warn, m.preflight.Fail)))
	}

	if len(m.found) > 0 {
		lines = append(lines, "", dimStyle.Render("Found"))
		start := len(m.found) - 10
		if start < 0 {
			start = 0
		}
		for _, result := range m.found[start:] {
			note := ""
			if result.Cached {
				note += dimStyle.Render(" (cached)")
			}
			if result.Method == "dns" {
				note += dimStyle.Render(" (DNS only, unverified)")
			}
			lines = append(lines, fmt.Sprintf("  + %-22s [%s]%s",
				result.Domain, result.Method, note))
		}
	}
	lines = append(lines, m.activityLines()...)
	return lines
}

func (m Model) pricingView(width int) []string {
	lines := []string{""}
	lines = append(lines, infoStyle.Render("Fetching tld-list prices")+
		dimStyle.Render(" — cheapest registration and renewal per TLD."))
	lines = append(lines, fmt.Sprintf("%-36s %s %s",
		bar(m.priceDone, m.priceTotal, 28),
		fmt.Sprintf("%d/%d", m.priceDone, m.priceTotal),
		m.spinnerFrame()))
	if m.priceTotal == 0 {
		lines = append(lines, dimStyle.Render("  checking the price cache ..."))
	}
	start := len(m.prices) - 8
	if start < 0 {
		start = 0
	}
	for _, line := range m.prices[start:] {
		if line.err != "" {
			lines = append(lines, fmt.Sprintf("  %s %-10s %s",
				failStyle.Render("✗"), line.tld,
				truncate(line.err, 60)))
			continue
		}
		reg, renewal := priceColumns(line.price)
		registrars := ""
		if line.price != nil {
			switch {
			case line.price.RegistrationRegistrar != "" && line.price.RenewalRegistrar != "":
				registrars = fmt.Sprintf("  (%s / %s)",
					line.price.RegistrationRegistrar,
					line.price.RenewalRegistrar)
			case line.price.RegistrationRegistrar != "":
				registrars = "  (" + line.price.RegistrationRegistrar + ")"
			case line.price.RenewalRegistrar != "":
				registrars = "  (" + line.price.RenewalRegistrar + ")"
			}
		}
		cached := ""
		if line.cached {
			cached = dimStyle.Render(" [cached]")
		}
		lines = append(lines, fmt.Sprintf("  %s %-10s %8s / %-8s%s%s",
			statusStyle(scanner.CheckOK).Render("✓"), line.tld,
			reg, renewal, registrars, cached))
	}
	return lines
}

func priceColumns(price *scanner.Price) (string, string) {
	if price == nil {
		return "-", "-"
	}
	currency := price.Currency
	if currency == "" {
		currency = "USD"
	}
	format := func(value float64) string {
		if value <= 0 {
			return "-"
		}
		if strings.EqualFold(currency, "USD") {
			return fmt.Sprintf("$%.2f", value)
		}
		return fmt.Sprintf("%.2f %s", value, currency)
	}
	return format(price.Registration), format(price.Renewal)
}

func resultHeader(bestPrice bool) string {
	header := fmt.Sprintf("  %-22s %4s  %-6s", "DOMAIN", "LEN", "METHOD")
	if bestPrice {
		header += fmt.Sprintf(" %8s %8s", "REG", "RENEW")
	}
	return header
}

func resultLine(result scanner.Result, bestPrice bool) string {
	line := fmt.Sprintf("  %-22s %4d  %-6s",
		result.Domain, result.Length, result.Method)
	if bestPrice {
		reg, renewal := priceColumns(result.Price)
		line += fmt.Sprintf(" %8s %8s", reg, renewal)
	}
	if result.Cached {
		line += dimStyle.Render(" (cached)")
	}
	if result.Method == "dns" {
		line += dimStyle.Render(" (unverified)")
	}
	return line
}

func (m Model) doneView(width int) []string {
	lines := []string{""}
	if m.err != nil {
		lines = append(lines, failStyle.Render("ERROR: "+m.err.Error()))
	}
	if m.summary != nil {
		summary := m.summary
		reason := summary.StopReason
		if reason == "" {
			reason = "finished"
		}
		if summary.Mode == "search" {
			lines = append(lines, fmt.Sprintf("%s · %s TLDs · %s",
				infoStyle.Render("DONE ("+reason+")"),
				formatInt(int64(summary.SearchTotal)),
				scanner.FormatDuration(summary.Elapsed)))
			lines = append(lines, dimStyle.Render(fmt.Sprintf(
				"  available %s · taken %s · unknown %s · canceled %s · cache %s",
				formatInt(summary.Stats.Available), formatInt(summary.Stats.Taken),
				formatInt(summary.Stats.Unknown), formatInt(summary.Stats.Canceled),
				formatInt(summary.Stats.CacheHits))))
			if len(summary.Results) == 0 {
				lines = append(lines, "", dimStyle.Render("No available domains found."))
			} else {
				lines = append(lines, "", dimStyle.Render(fmt.Sprintf(
					"Available domains for %s", summary.SearchLabel)))
				sorted := append([]scanner.Result(nil), summary.Results...)
				if summary.Plan.BestPrice {
					scanner.SortByRenewal(sorted)
				} else {
					sort.Slice(sorted, func(i, j int) bool {
						if sorted[i].Length != sorted[j].Length {
							return sorted[i].Length < sorted[j].Length
						}
						return sorted[i].Domain < sorted[j].Domain
					})
				}
				bestPrice := summary.Plan.BestPrice
				lines = append(lines, dimStyle.Render(resultHeader(bestPrice)))
				for _, result := range sorted {
					lines = append(lines, resultLine(result, bestPrice))
				}
			}
			return lines
		}
		lines = append(lines, fmt.Sprintf("%s · %s checked · %s",
			infoStyle.Render("DONE ("+reason+")"),
			formatInt(summary.Stats.Checked),
			scanner.FormatDuration(summary.Elapsed)))
		lines = append(lines, dimStyle.Render(fmt.Sprintf(
			"  found %s · taken %s · unknown %s · canceled %s · cache %s",
			formatInt(summary.Stats.Available), formatInt(summary.Stats.Taken),
			formatInt(summary.Stats.Unknown), formatInt(summary.Stats.Canceled),
			formatInt(summary.Stats.CacheHits))))
		if len(summary.Results) == 0 {
			lines = append(lines, "", dimStyle.Render("No available domains found in the scanned range."))
		} else {
			lines = append(lines, "", dimStyle.Render(fmt.Sprintf(
				"Shortest available domains (%d characters)", summary.Shortest)))
			bestPrice := summary.Plan.BestPrice
			lines = append(lines, dimStyle.Render(resultHeader(bestPrice)))
			sorted := append([]scanner.Result(nil), summary.Results...)
			if bestPrice {
				scanner.SortByRenewal(sorted)
			}
			for _, result := range sorted {
				lines = append(lines, resultLine(result, bestPrice))
			}
		}
	} else if m.closed {
		lines = append(lines, warnStyle.Render("STOPPED"))
	}
	return lines
}

func (m Model) activityLines() []string {
	if len(m.logs) == 0 {
		return nil
	}
	lines := []string{"", dimStyle.Render("Activity")}
	start := len(m.logs) - 5
	if start < 0 {
		start = 0
	}
	for _, line := range m.logs[start:] {
		lines = append(lines, "  "+logStyle(line.level).Render(line.text))
	}
	return lines
}

func (m Model) footer() string {
	if m.finished || m.closed {
		return dimStyle.Render("press q to quit")
	}
	return dimStyle.Render("q quit · ctrl+c cancel scan")
}

func (m Model) spinnerFrame() string {
	return spinnerFrames[m.spinner%len(spinnerFrames)]
}

func (m Model) proxyLabel() string {
	if m.plan == nil {
		return "proxy: loading"
	}
	if m.plan.ProxyCount == 0 {
		return "HTTP: direct"
	}
	return fmt.Sprintf("HTTP: %d proxies from %s", m.plan.ProxyCount, m.plan.ProxyFile)
}

func phaseLabel(phase scanner.Phase) string {
	switch phase {
	case scanner.PhaseLoading:
		return "LOADING"
	case scanner.PhasePreflight:
		return "CONNECTING"
	case scanner.PhaseScanning:
		return "SCANNING"
	case scanner.PhaseSearching:
		return "SEARCHING"
	case scanner.PhasePricing:
		return "PRICING"
	case scanner.PhaseDone:
		return "DONE"
	case scanner.PhaseError:
		return "ERROR"
	default:
		return strings.ToUpper(string(phase))
	}
}

func phaseStyle(phase scanner.Phase) lipgloss.Style {
	switch phase {
	case scanner.PhaseScanning, scanner.PhaseSearching, scanner.PhaseDone:
		return okStyle.Bold(true)
	case scanner.PhasePricing:
		return warnStyle.Bold(true)
	case scanner.PhasePreflight:
		return warnStyle.Bold(true)
	case scanner.PhaseError:
		return failStyle.Bold(true)
	default:
		return infoStyle.Bold(true)
	}
}

func statusStyle(status scanner.CheckStatus) lipgloss.Style {
	switch status {
	case scanner.CheckOK:
		return okStyle
	case scanner.CheckWarn:
		return warnStyle
	case scanner.CheckFail:
		return failStyle
	default:
		return dimStyle
	}
}

func checkSymbol(status scanner.CheckStatus) string {
	switch status {
	case scanner.CheckOK:
		return "✓"
	case scanner.CheckWarn:
		return "!"
	case scanner.CheckFail:
		return "✗"
	case scanner.CheckSkip:
		return "-"
	default:
		return "…"
	}
}

func renderCheck(check scanner.CheckResult) string {
	latency := ""
	if check.Latency > 0 {
		latency = " " + formatLatency(check.Latency)
	}
	detail := check.Detail
	if len(detail) > 42 {
		detail = detail[:39] + "..."
	}
	return fmt.Sprintf("%s %-6s %-34s%s  %s",
		statusStyle(check.Status).Render(checkSymbol(check.Status)),
		check.Kind, truncate(check.Target, 34), latency, detail)
}

func recentFailures(checks []scanner.CheckResult, limit int) []scanner.CheckResult {
	var failures []scanner.CheckResult
	for i := len(checks) - 1; i >= 0 && len(failures) < limit; i-- {
		if checks[i].Status == scanner.CheckFail || checks[i].Status == scanner.CheckWarn {
			failures = append(failures, checks[i])
		}
	}
	for i, j := 0, len(failures)-1; i < j; i, j = i+1, j-1 {
		failures[i], failures[j] = failures[j], failures[i]
	}
	return failures
}

func logStyle(level scanner.LogLevel) lipgloss.Style {
	switch level {
	case scanner.LogError:
		return failStyle
	case scanner.LogWarn:
		return warnStyle
	default:
		return dimStyle
	}
}

func bar(done, total, width int) string {
	if total <= 0 {
		return ""
	}
	ratio := float64(done) / float64(total)
	if ratio > 1 {
		ratio = 1
	}
	filled := int(ratio * float64(width))
	return "[" + strings.Repeat("█", filled) +
		strings.Repeat("░", width-filled) + "]"
}

func truncate(value string, width int) string {
	if len(value) <= width {
		return value
	}
	if width <= 3 {
		return value[:width]
	}
	return value[:width-3] + "..."
}

func formatLatency(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func formatInt(n int64) string {
	value := fmt.Sprintf("%d", n)
	if len(value) <= 3 {
		return value
	}
	var parts []string
	for len(value) > 3 {
		parts = append([]string{value[len(value)-3:]}, parts...)
		value = value[:len(value)-3]
	}
	parts = append([]string{value}, parts...)
	return strings.Join(parts, ",")
}
