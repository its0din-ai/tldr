package app

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/its0din-ai/tldr/internal/buildinfo"
	"github.com/its0din-ai/tldr/internal/scanner"
)

type plainPrinter struct {
	out          io.Writer
	lastProgress time.Time
	phase        scanner.Phase
	plan         *scanner.Plan
	planPrinted  bool
}

func newPlainPrinter(out io.Writer) *plainPrinter {
	return &plainPrinter{out: out, lastProgress: time.Now()}
}

func (p *plainPrinter) Handle(event scanner.Event) {
	switch event.Type {
	case scanner.EventPlan:
		if p.planPrinted || event.Plan == nil {
			return
		}
		p.planPrinted = true
		p.plan = event.Plan
		plan := event.Plan
		fmt.Fprintf(p.out, "tldr-scanner %s (%s)\n",
			buildinfo.Version, buildinfo.Platform())
		if plan.Mode == "search" {
			if plan.TLDsExplicit {
				fmt.Fprintf(p.out, "Search: %s across %d selected TLDs\n",
					plan.SearchLabel, plan.SearchTotal)
			} else {
				fmt.Fprintf(p.out, "Search: %s across %d TLDs (max TLD length %d)\n",
					plan.SearchLabel, plan.SearchTotal, plan.MaxTLDLen)
			}
		} else {
			fmt.Fprintf(p.out, "TLDs: %d selected (%d with RDAP, %d WHOIS/DNS)\n",
				plan.TLDCount, plan.RDAPCount, plan.WHOISCount)
			fmt.Fprintf(p.out, "Length range: %d..%d characters\n",
				plan.MinLength, plan.MaxLength)
		}
		if plan.ProxyCount > 0 {
			fmt.Fprintf(p.out, "HTTP: %d proxy endpoints from %s\n",
				plan.ProxyCount, plan.ProxyFile)
		} else {
			fmt.Fprintln(p.out, "HTTP: direct (no proxy file)")
		}
		fmt.Fprintf(p.out, "Data: %s\n", plan.DataDir)
		if plan.Mode == "search" {
			fmt.Fprintf(p.out, "Targets: %d domains, %d concurrent lookups\n",
				plan.SearchTotal, plan.Concurrency)
		} else {
			fmt.Fprintf(p.out, "Stop after: %d available, %d checks max, %d concurrent lookups\n",
				plan.Limit, plan.MaxChecks, plan.Concurrency)
		}
		if plan.BestPrice {
			fmt.Fprintln(p.out, "Prices: tld-list.com cheapest registration/renewal")
		}
		if plan.Mode != "search" && plan.Sequential != "" {
			fmt.Fprintf(p.out, "Sequential prefix: %s\n", plan.Sequential)
		}
		fmt.Fprintf(p.out, "Seed: %d\n", plan.Seed)

	case scanner.EventPhase:
		p.phase = event.Phase
		switch event.Phase {
		case scanner.PhaseLoading:
			fmt.Fprintln(p.out, "\nLoading IANA TLD/RDAP data ...")
		case scanner.PhasePreflight:
			fmt.Fprintln(p.out, "\nConnectivity checks ...")
		case scanner.PhaseScanning:
			fmt.Fprintln(p.out, "\nScanning ...")
		case scanner.PhaseSearching:
			label, total := "", 0
			if p.plan != nil {
				label, total = p.plan.SearchLabel, p.plan.SearchTotal
			}
			fmt.Fprintf(p.out, "\nSearching %s across %d TLDs ...\n", label, total)
		case scanner.PhasePricing:
			fmt.Fprintln(p.out, "\nFetching tld-list prices ...")
		case scanner.PhaseDone:
			// Final summary is rendered by EventDone.
		}

	case scanner.EventLog:
		fmt.Fprintf(p.out, "  [%s] %s\n", event.Level, event.Message)

	case scanner.EventPreflightPlan:
		fmt.Fprintf(p.out, "  %d endpoints to check\n", event.CheckTotal)

	case scanner.EventPreflightCheck:
		if event.Check == nil {
			return
		}
		check := *event.Check
		fmt.Fprintf(p.out, "  %s %-5s %-42s %6s %s\n",
			checkSymbol(check.Status),
			check.Kind,
			check.Target,
			formatLatency(check.Latency),
			check.Detail,
		)

	case scanner.EventPreflightDone:
		if event.Preflight == nil {
			return
		}
		summary := *event.Preflight
		fmt.Fprintf(p.out, "  connectivity: %d ok, %d warn, %d failed, %d skipped (of %d)\n",
			summary.OK, summary.Warn, summary.Fail, summary.Skip, summary.Total)

	case scanner.EventProgress:
		now := time.Now()
		if !p.lastProgress.IsZero() && now.Sub(p.lastProgress) < 5*time.Second {
			return
		}
		p.lastProgress = now
		progress := event.Progress
		if progress.Total > 0 {
			fmt.Fprintf(p.out,
				"  ... %d/%d TLDs | %d available | %.1f/s | active %d | %s\n",
				progress.Checked, progress.Total, progress.Found,
				progress.Rate, progress.Active,
				scanner.FormatDuration(progress.Elapsed))
		} else {
			fmt.Fprintf(p.out,
				"  ... %d checked | %d found | %.1f/s | active %d | %s | taken %d unknown %d\n",
				progress.Checked, progress.Found, progress.Rate, progress.Active,
				scanner.FormatDuration(progress.Elapsed), progress.Taken, progress.Unknown)
		}

	case scanner.EventFound:
		result := event.Result
		note := ""
		if result.Cached {
			note += " (cached)"
		}
		if result.Method == "dns" {
			note += " (DNS only, unverified)"
		}
		fmt.Fprintf(p.out, "  + %-22s [%s]%s\n",
			result.Domain, result.Method, note)

	case scanner.EventPricing:
		pricing := event.Pricing
		if pricing.TLD == "" {
			return
		}
		if pricing.Err != "" {
			fmt.Fprintf(p.out, "  ✗ %-10s %s\n", pricing.TLD, pricing.Err)
			return
		}
		reg, renewal := formatPriceColumns(pricing.Price)
		cached := ""
		if pricing.Cached {
			cached = " [cached]"
		}
		fmt.Fprintf(p.out, "  ✓ %-10s %8s / %-8s%s\n",
			pricing.TLD, reg, renewal, cached)

	case scanner.EventDone:
		scanner.RenderSummary(p.out, event.Summary)

	case scanner.EventError:
		if event.Err != nil {
			fmt.Fprintf(p.out, "\nerror: %v\n", event.Err)
		}
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

func formatLatency(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func formatPriceColumns(price *scanner.Price) (string, string) {
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
