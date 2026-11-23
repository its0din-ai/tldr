package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/its0din-ai/tldr/internal/app"
	"github.com/its0din-ai/tldr/internal/buildinfo"
	"github.com/its0din-ai/tldr/internal/scanner"
	"github.com/its0din-ai/tldr/internal/tui"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	parsed, err := app.ParseFlags(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	if parsed.ShowVersion {
		fmt.Printf("tldr-scanner %s (%s)\n",
			buildinfo.Full(), buildinfo.Platform())
		return 0
	}
	cfg := parsed.Config

	signalCtx, stop := signal.NotifyContext(
		context.Background(), os.Interrupt, syscall.SIGTERM,
	)
	defer stop()

	if cfg.ListTLDs || cfg.DryRun {
		if app.RunDirect(signalCtx, cfg, os.Stdout) != 0 {
			return 1
		}
		return 0
	}

	tuiEnabled := !cfg.NoTUI && isTTY(os.Stdin) && isTTY(os.Stdout)
	if !tuiEnabled {
		if app.RunPlain(signalCtx, cfg, os.Stdout) != 0 {
			return 1
		}
		if signalCtx.Err() != nil {
			return 130
		}
		return 0
	}

	ctx, cancel := context.WithCancel(signalCtx)
	defer cancel()

	events := make(chan scanner.Event, 1024)
	resultCh := make(chan app.RunResult, 1)
	go func() {
		summary, runErr := app.Run(ctx, cfg, events)
		resultCh <- app.RunResult{Summary: summary, Err: runErr}
	}()

	model := tui.New(cancel, events)
	program := tea.NewProgram(model, tea.WithAltScreen())
	_, runErr := program.Run()
	cancel()
	result := <-resultCh

	if result.Summary != nil {
		scanner.RenderSummary(os.Stdout, result.Summary)
	}
	if runErr != nil && !errors.Is(runErr, tea.ErrProgramKilled) {
		fmt.Fprintf(os.Stderr, "tui error: %v\n", runErr)
		return 1
	}
	if result.Err != nil && ctx.Err() == nil && signalCtx.Err() == nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", result.Err)
		return 1
	}
	if signalCtx.Err() != nil {
		return 130
	}
	return 0
}

func isTTY(file *os.File) bool {
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
