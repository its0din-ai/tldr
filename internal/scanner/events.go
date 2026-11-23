package scanner

import (
	"context"
	"fmt"
	"time"
)

type Phase string

const (
	PhaseLoading   Phase = "loading"
	PhasePreflight Phase = "connectivity"
	PhaseScanning  Phase = "scanning"
	PhaseSearching Phase = "searching"
	PhasePricing   Phase = "pricing"
	PhaseDone      Phase = "done"
	PhaseError     Phase = "error"
)

type LogLevel string

const (
	LogInfo  LogLevel = "info"
	LogWarn  LogLevel = "warn"
	LogError LogLevel = "error"
)

type EventType int

const (
	EventPlan EventType = iota
	EventPhase
	EventLog
	EventPreflightPlan
	EventPreflightCheck
	EventPreflightDone
	EventProgress
	EventFound
	EventPricing
	EventDone
	EventError
)

type Progress struct {
	Level        int
	Checked      int64
	MaxChecks    int
	Found        int64
	Limit        int
	Total        int
	Taken        int64
	Unknown      int64
	Canceled     int64
	CacheHits    int64
	DNSQueries   int64
	RDAPQueries  int64
	WHOISQueries int64
	Active       int64
	Elapsed      time.Duration
	Rate         float64
}

type CheckKind string

const (
	CheckDNS   CheckKind = "dns"
	CheckProxy CheckKind = "proxy"
	CheckRDAP  CheckKind = "rdap"
	CheckWHOIS CheckKind = "whois"
)

type CheckStatus string

const (
	CheckPending CheckStatus = "pending"
	CheckOK      CheckStatus = "ok"
	CheckWarn    CheckStatus = "warn"
	CheckFail    CheckStatus = "fail"
	CheckSkip    CheckStatus = "skip"
)

type CheckResult struct {
	Kind    CheckKind
	Target  string
	Status  CheckStatus
	Latency time.Duration
	Detail  string
}

type PricingProgress struct {
	Done   int
	Total  int
	TLD    string
	Price  *Price
	Err    string
	Cached bool
}

type PreflightSummary struct {
	Total int
	OK    int
	Warn  int
	Fail  int
	Skip  int
}

func (p PreflightSummary) Failed() bool {
	return p.Fail > 0
}

type Event struct {
	Type EventType
	Plan *Plan

	Phase Phase

	Level   LogLevel
	Message string

	Checks []CheckResult
	Check  *CheckResult

	CheckDone  int
	CheckTotal int
	Preflight  *PreflightSummary

	Progress Progress
	Pricing  PricingProgress
	Result   Result
	Summary  *Summary
	Err      error
}

// Emitter sends UI events. Progress events are best-effort; important events
// wait for the UI but stop when the context is canceled.
type Emitter struct {
	ctx context.Context
	ch  chan<- Event
}

func NewEmitter(ctx context.Context, ch chan<- Event) *Emitter {
	return &Emitter{ctx: ctx, ch: ch}
}

func (e *Emitter) Send(event Event) {
	if e == nil || e.ch == nil {
		return
	}
	select {
	case e.ch <- event:
	case <-e.ctx.Done():
	}
}

func (e *Emitter) TrySend(event Event) {
	if e == nil || e.ch == nil {
		return
	}
	select {
	case e.ch <- event:
	default:
	}
}

func (e *Emitter) Phase(phase Phase) {
	e.Send(Event{Type: EventPhase, Phase: phase})
}

func (e *Emitter) Log(level LogLevel, message string) {
	e.Send(Event{Type: EventLog, Level: level, Message: message})
}

func (e *Emitter) Logf(level LogLevel, format string, args ...any) {
	e.Log(level, fmt.Sprintf(format, args...))
}
