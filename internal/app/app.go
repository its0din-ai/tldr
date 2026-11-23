package app

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/its0din-ai/tldr/internal/scanner"
)

// Run executes a scan and publishes UI events. It owns the events channel and
// closes it before returning.
func Run(
	ctx context.Context,
	cfg scanner.Config,
	events chan<- scanner.Event,
) (*scanner.Summary, error) {
	emit := scanner.NewEmitter(ctx, events)
	defer close(events)

	emit.Phase(scanner.PhaseLoading)
	s, err := scanner.New(ctx, cfg, emit)
	if err != nil {
		emit.Send(scanner.Event{Type: scanner.EventError, Err: err})
		return nil, err
	}
	defer s.Close()

	if cfg.ListTLDs || cfg.DryRun {
		mode := "list"
		if cfg.DryRun {
			mode = "dry-run"
			s.DryRun(os.Stdout)
		} else {
			s.ListTLDs(os.Stdout)
		}
		emit.Phase(scanner.PhaseDone)
		return &scanner.Summary{Mode: mode, Plan: s.Plan()}, nil
	}

	cachedReady := false
	if cfg.Search == "" && !cfg.SkipCache {
		cachedReady = len(s.CachedResults(cfg.Limit)) >= cfg.Limit
	}

	if cachedReady {
		emit.Log(scanner.LogInfo,
			"cached available domains fill the limit; skipping checks "+
				"(use -skip-cache to refresh)")
	} else if !cfg.SkipPreflight {
		emit.Phase(scanner.PhasePreflight)
		checks := s.Preflight(ctx)
		summary := scanner.SummarizeChecks(checks)
		if summary.Failed() {
			emit.Logf(scanner.LogWarn, "connectivity: %d ok, %d warn, %d failed",
				summary.OK, summary.Warn, summary.Fail)
			if cfg.RequirePreflight {
				err := fmt.Errorf(
					"connectivity check failed for %d endpoint(s); "+
						"re-run without -require-preflight to continue anyway",
					summary.Fail,
				)
				emit.Send(scanner.Event{Type: scanner.EventError, Err: err})
				return nil, err
			}
		} else {
			emit.Logf(scanner.LogInfo, "connectivity: %d ok, %d warn",
				summary.OK, summary.Warn)
		}
	} else {
		emit.Logf(scanner.LogInfo, "connectivity checks skipped (-skip-preflight)")
	}

	if ctx.Err() != nil {
		emit.Phase(scanner.PhaseDone)
		mode := "scan"
		if cfg.Search != "" {
			mode = "search"
		}
		return &scanner.Summary{
			Mode:        mode,
			SearchLabel: cfg.Search,
			SearchTotal: len(s.TLDs()),
			Plan:        s.Plan(),
			StopReason:  "interrupted",
		}, nil
	}

	var summary *scanner.Summary
	var scanErr error
	if cfg.Search != "" {
		emit.Phase(scanner.PhaseSearching)
		summary, scanErr = s.Search(ctx)
	} else {
		emit.Phase(scanner.PhaseScanning)
		summary, scanErr = s.Scan(ctx)
	}
	if scanErr != nil {
		emit.Send(scanner.Event{Type: scanner.EventError, Err: scanErr})
		return summary, scanErr
	}
	if cfg.BestPrice && summary != nil && len(summary.Results) > 0 {
		emit.Phase(scanner.PhasePricing)
		priced, priceErr := s.EnrichPrices(ctx, emit)
		summary.Results = s.Results()
		summary.Priced = priced
		if priceErr != nil {
			emit.Logf(scanner.LogWarn, "price lookup: %v", priceErr)
		}
	}
	if err := s.WriteOutputs(); err != nil {
		summary.Err = err
		emit.Send(scanner.Event{Type: scanner.EventError, Err: err})
		return summary, err
	}
	emit.Phase(scanner.PhaseDone)
	emit.Send(scanner.Event{Type: scanner.EventDone, Summary: summary})
	return summary, nil
}

// RunDirect handles modes that print data and exit (no scanning, no events).
func RunDirect(ctx context.Context, cfg scanner.Config, out io.Writer) int {
	emit := scanner.NewEmitter(ctx, nil)
	s, err := scanner.New(ctx, cfg, emit)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 1
	}
	defer s.Close()
	if cfg.DryRun {
		s.DryRun(out)
	} else {
		s.ListTLDs(out)
	}
	return 0
}

type RunResult struct {
	Summary *scanner.Summary
	Err     error
}

// RunPlain runs a scan without the interactive TUI.
func RunPlain(ctx context.Context, cfg scanner.Config, out io.Writer) int {
	events := make(chan scanner.Event, 512)
	resultCh := make(chan RunResult, 1)
	go func() {
		summary, err := Run(ctx, cfg, events)
		resultCh <- RunResult{Summary: summary, Err: err}
	}()

	printer := newPlainPrinter(out)
	for event := range events {
		printer.Handle(event)
	}
	result := <-resultCh
	if result.Err != nil {
		return 1
	}
	return 0
}
