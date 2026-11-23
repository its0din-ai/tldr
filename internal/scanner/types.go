package scanner

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/its0din-ai/tldr/internal/buildinfo"
)

const (
	ianaTLDsURL  = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
	ianaRDAPURL  = "https://data.iana.org/rdap/dns.json"
	whoisIANA    = "whois.iana.org"
	cacheDir     = ".data"
	bootstrapTTL = 7 * 24 * time.Hour
	maxDNSLabel  = 63
)

type Config struct {
	TLDsRaw     string
	TLDLengths  []int
	ExcludeRaw  string
	MinLabel    int
	MaxLen      int
	Limit       int
	Alphabet    string
	Sequential  string
	Seed        int64
	Concurrency int
	Timeout     time.Duration

	Search    string
	MaxTLDLen int

	RDAPPerHost int
	MaxChecks   int
	NoRDAP      bool
	NoWHOIS     bool
	WHOISDelay  time.Duration

	CachePath string
	CacheTTL  time.Duration
	SkipCache bool

	JSONPath string
	CSVPath  string

	BestPrice         bool
	TLDListPublicKey  string
	TLDListPrivateKey string

	ListTLDs bool
	DryRun   bool
	Verbose  bool

	ProxyFile string
	Proxies   []string

	SkipPreflight        bool
	RequirePreflight     bool
	PreflightConcurrency int
	PreflightTimeout     time.Duration

	NoTUI bool
}

type Plan struct {
	Mode          string
	BestPrice     bool
	Sequential    string
	SearchLabel   string
	MaxTLDLen     int
	SearchTotal   int
	TLDsExplicit  bool
	TLDCount      int
	RDAPCount     int
	WHOISCount    int
	MinLength     int
	MaxLength     int
	Limit         int
	MaxChecks     int
	Concurrency   int
	ProxyCount    int
	ProxyFile     string
	Seed          int64
	PreflightOn   bool
	PreflightJobs int
}

type Price struct {
	Registration          float64 `json:"registration"`
	Renewal               float64 `json:"renewal"`
	Currency              string  `json:"currency"`
	RegistrationRegistrar string  `json:"registration_registrar,omitempty"`
	RenewalRegistrar      string  `json:"renewal_registrar,omitempty"`
	Source                string  `json:"source,omitempty"`
}

type Result struct {
	Domain string `json:"domain"`
	Length int    `json:"length"`
	Status string `json:"status"`
	Method string `json:"method"`
	Detail string `json:"detail"`
	Cached bool   `json:"cached"`
	Price  *Price `json:"price,omitempty"`
}

type StatsSnapshot struct {
	Checked      int64
	Available    int64
	Taken        int64
	Unknown      int64
	Canceled     int64
	CacheHits    int64
	DNSQueries   int64
	RDAPQueries  int64
	WHOISQueries int64
}

type Summary struct {
	Mode        string
	SearchLabel string
	SearchTotal int
	Plan        Plan
	Results     []Result
	Shortest    int
	Priced      int
	Stats       StatsSnapshot
	Elapsed     time.Duration
	StopReason  string
	Err         error
}

type Stats struct {
	Checked      atomic.Int64
	Available    atomic.Int64
	Taken        atomic.Int64
	Unknown      atomic.Int64
	Canceled     atomic.Int64
	CacheHits    atomic.Int64
	DNSQueries   atomic.Int64
	RDAPQueries  atomic.Int64
	WHOISQueries atomic.Int64
	Active       atomic.Int64
}

func (s *Stats) Snapshot() StatsSnapshot {
	return StatsSnapshot{
		Checked:      s.Checked.Load(),
		Available:    s.Available.Load(),
		Taken:        s.Taken.Load(),
		Unknown:      s.Unknown.Load(),
		Canceled:     s.Canceled.Load(),
		CacheHits:    s.CacheHits.Load(),
		DNSQueries:   s.DNSQueries.Load(),
		RDAPQueries:  s.RDAPQueries.Load(),
		WHOISQueries: s.WHOISQueries.Load(),
	}
}

// keyedSemaphores hands out a bounded channel per key (registry host, WHOIS
// server, etc.) so one slow endpoint cannot starve the others.
type keyedSemaphores struct {
	mu    sync.Mutex
	chans map[string]chan struct{}
}

func newKeyedSemaphores() *keyedSemaphores {
	return &keyedSemaphores{chans: make(map[string]chan struct{})}
}

func (k *keyedSemaphores) get(key string, capacity int) chan struct{} {
	if capacity < 1 {
		capacity = 1
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	ch, ok := k.chans[key]
	if !ok {
		ch = make(chan struct{}, capacity)
		k.chans[key] = ch
	}
	return ch
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func userAgent() string {
	return "tldr-scanner/" + buildinfo.Version +
		" (domain availability scanner; +https://github.com/its0din-ai/tldr)"
}
