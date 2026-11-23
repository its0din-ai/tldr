package scanner

import (
	"context"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/its0din-ai/tldr/internal/buildinfo"
)

type Scanner struct {
	cfg     Config
	emit    *Emitter
	tlds    []string
	rdapMap map[string]string

	dns   *DNSResolver
	rdap  *RDAPClient
	whois *WHOISClient
	cache *Cache
	proxy *ProxyPool
	stats *Stats
	rng   *rand.Rand

	transport       *http.Transport
	bootstrapClient *http.Client
	preflightClient *http.Client
	priceClient     *http.Client

	level atomic.Int64

	mu         sync.Mutex
	found      []Result
	foundSet   map[string]struct{}
	stopReason string
}

func New(ctx context.Context, cfg Config, emit *Emitter) (*Scanner, error) {
	proxyPool := NewProxyPool(cfg.Proxies)
	transport := newHTTPTransport()
	bootstrapClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	allTLDs, err := loadTLDs(ctx, bootstrapClient, proxyPool, cacheDir)
	if err != nil {
		return nil, err
	}
	tlds, err := selectTLDs(allTLDs, &cfg)
	if err != nil {
		return nil, err
	}
	if cfg.Sequential != "" && cfg.Search == "" {
		if err := validateSequentialPrefix(
			cfg.Sequential, tlds, cfg.MaxLen,
		); err != nil {
			return nil, err
		}
	}
	rdapMap, err := loadRDAPMap(ctx, bootstrapClient, proxyPool, cacheDir)
	if err != nil {
		return nil, err
	}
	cache, err := NewCache(cfg.CachePath, cfg.CacheTTL, cfg.SkipCache)
	if err != nil {
		return nil, err
	}

	stats := &Stats{}
	scanner := &Scanner{
		cfg:             cfg,
		emit:            emit,
		tlds:            tlds,
		rdapMap:         rdapMap,
		dns:             newDNSResolver(cfg.Timeout),
		stats:           stats,
		cache:           cache,
		proxy:           proxyPool,
		rng:             rand.New(rand.NewSource(cfg.Seed)),
		foundSet:        make(map[string]struct{}),
		transport:       transport,
		bootstrapClient: bootstrapClient,
		preflightClient: &http.Client{
			Timeout:   cfg.PreflightTimeout,
			Transport: transport,
		},
		priceClient: &http.Client{
			Timeout:   25 * time.Second,
			Transport: transport,
		},
	}
	scanner.rdap = &RDAPClient{
		client: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
		},
		proxy:   proxyPool,
		perHost: cfg.RDAPPerHost,
		sems:    newKeyedSemaphores(),
		stats:   stats,
	}
	scanner.whois = newWHOISClient(cfg.Timeout, cfg.WHOISDelay, stats, cache)

	plan := scanner.Plan()
	emit.Send(Event{Type: EventPlan, Plan: &plan})
	return scanner, nil
}

func (s *Scanner) Plan() Plan {
	rdapCount := 0
	if !s.cfg.NoRDAP {
		for _, tld := range s.tlds {
			if _, ok := s.rdapMap[tld]; ok {
				rdapCount++
			}
		}
	}
	whoisCount := 0
	if !s.cfg.NoWHOIS {
		for _, tld := range s.tlds {
			if _, ok := s.rdapMap[tld]; !ok || s.cfg.NoRDAP {
				whoisCount++
			}
		}
	}
	start, end := s.levelRange()
	preflightJobs := 0
	if !s.cfg.SkipPreflight {
		preflightJobs = 1 + s.proxy.Len()
		seen := make(map[string]struct{})
		if !s.cfg.NoRDAP {
			for _, tld := range s.tlds {
				base, ok := s.rdapMap[tld]
				if !ok {
					continue
				}
				if _, dup := seen[base]; dup {
					continue
				}
				seen[base] = struct{}{}
				preflightJobs++
			}
		}
		if !s.cfg.NoWHOIS {
			for _, tld := range s.tlds {
				if _, ok := s.rdapMap[tld]; !ok || s.cfg.NoRDAP {
					preflightJobs++
				}
			}
		}
	}
	mode := "scan"
	if s.cfg.Search != "" {
		mode = "search"
	}
	return Plan{
		Mode:          mode,
		BestPrice:     s.cfg.BestPrice,
		Sequential:    s.cfg.Sequential,
		SearchLabel:   s.cfg.Search,
		MaxTLDLen:     s.cfg.MaxTLDLen,
		SearchTotal:   len(s.tlds),
		TLDsExplicit:  s.cfg.TLDsRaw != "",
		TLDCount:      len(s.tlds),
		RDAPCount:     rdapCount,
		WHOISCount:    whoisCount,
		MinLength:     start,
		MaxLength:     end,
		Limit:         s.cfg.Limit,
		MaxChecks:     s.cfg.MaxChecks,
		Concurrency:   s.cfg.Concurrency,
		ProxyCount:    s.proxy.Len(),
		ProxyFile:     s.cfg.ProxyFile,
		Seed:          s.cfg.Seed,
		PreflightOn:   !s.cfg.SkipPreflight,
		PreflightJobs: preflightJobs,
	}
}

func (s *Scanner) Close() error {
	if s.transport != nil {
		s.transport.CloseIdleConnections()
	}
	return s.cache.Close()
}

func (s *Scanner) TLDs() []string {
	return s.tlds
}

func (s *Scanner) RDAPMap() map[string]string {
	return s.rdapMap
}

// Preflight checks DNS, proxies, RDAP registries, and WHOIS servers. It emits
// its own events so the TUI/plain UI can show why startup takes time.
func (s *Scanner) Preflight(ctx context.Context) []CheckResult {
	tasks := s.buildPreflightTasks()
	checks := make([]CheckResult, len(tasks))
	for i, task := range tasks {
		checks[i] = task.check
	}
	s.emit.Send(Event{
		Type:       EventPreflightPlan,
		Checks:     checks,
		CheckTotal: len(checks),
	})
	if len(tasks) == 0 {
		summary := PreflightSummary{}
		s.emit.Send(Event{Type: EventPreflightDone, Preflight: &summary})
		return checks
	}

	concurrency := s.cfg.PreflightConcurrency
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var done atomic.Int64

	for i := range tasks {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			result := s.runPreflightTask(ctx, tasks[index])
			<-sem
			checks[index] = result
			completed := done.Add(1)
			s.emit.Send(Event{
				Type:       EventPreflightCheck,
				Check:      &result,
				CheckDone:  int(completed),
				CheckTotal: len(tasks),
			})
		}(i)
	}
	wg.Wait()

	summary := SummarizeChecks(checks)
	s.emit.Send(Event{Type: EventPreflightDone, Preflight: &summary})
	return checks
}

type preflightTask struct {
	check      CheckResult
	base       string
	proxyIndex int
	tld        string
}

func (s *Scanner) buildPreflightTasks() []preflightTask {
	var tasks []preflightTask
	tasks = append(tasks, preflightTask{
		check: CheckResult{Kind: CheckDNS, Target: "system resolver", Status: CheckPending},
	})

	for i := range s.proxy.Templates() {
		tasks = append(tasks, preflightTask{
			check: CheckResult{
				Kind:   CheckProxy,
				Target: fmt.Sprintf("proxy #%d %s", i+1, SafeProxyName(s.proxy.Templates()[i])),
				Status: CheckPending,
			},
			proxyIndex: i,
		})
	}

	if !s.cfg.NoRDAP {
		seen := make(map[string]struct{})
		for _, tld := range s.tlds {
			base, ok := s.rdapMap[tld]
			if !ok {
				continue
			}
			if _, dup := seen[base]; dup {
				continue
			}
			seen[base] = struct{}{}
			tasks = append(tasks, preflightTask{
				check: CheckResult{
					Kind:   CheckRDAP,
					Target: upstreamHost(base),
					Status: CheckPending,
				},
				base: base,
			})
		}
	}

	if !s.cfg.NoWHOIS {
		for _, tld := range s.tlds {
			if _, ok := s.rdapMap[tld]; ok && !s.cfg.NoRDAP {
				continue
			}
			tasks = append(tasks, preflightTask{
				check: CheckResult{
					Kind:   CheckWHOIS,
					Target: tld,
					Status: CheckPending,
				},
				tld: tld,
			})
		}
	}
	return tasks
}

func (s *Scanner) runPreflightTask(
	ctx context.Context,
	task preflightTask,
) CheckResult {
	start := time.Now()
	result := task.check
	switch task.check.Kind {
	case CheckDNS:
		result.Status, result.Detail, result.Latency = s.checkDNS(ctx)
	case CheckProxy:
		result.Status, result.Detail, result.Latency = s.checkProxy(ctx, task.proxyIndex)
	case CheckRDAP:
		result.Status, result.Detail, result.Latency = s.checkRDAP(ctx, task.base)
	case CheckWHOIS:
		result.Status, result.Detail, result.Latency = s.checkWHOIS(ctx, task.tld)
	}
	if result.Latency == 0 {
		result.Latency = time.Since(start)
	}
	return result
}

func (s *Scanner) checkDNS(
	ctx context.Context,
) (CheckStatus, string, time.Duration) {
	const target = "system resolver"
	if cached, ok := s.cache.GetCheck(kindDNS, target); ok {
		return CheckStatus(cached.Status), cached.Detail + " (cached)", cached.Latency
	}

	start := time.Now()
	status, detail := s.dns.probe(ctx, "example.com")
	checkStatus := CheckFail
	if status != "unknown" {
		checkStatus = CheckOK
	}
	latency := time.Since(start)
	s.cache.PutCheck(kindDNS, target, string(checkStatus), detail, latency)
	return checkStatus, detail, latency
}

func (s *Scanner) checkProxy(
	ctx context.Context,
	index int,
) (CheckStatus, string, time.Duration) {
	template := s.proxy.Templates()[index]
	if cached, ok := s.cache.GetCheck(kindProxy, template); ok {
		return CheckStatus(cached.Status), cached.Detail + " (cached)", cached.Latency
	}

	start := time.Now()
	finish := func(status CheckStatus, detail string) (CheckStatus, string, time.Duration) {
		latency := time.Since(start)
		s.cache.PutCheck(kindProxy, template, string(status), detail, latency)
		return status, detail, latency
	}

	requestCtx, cancel := context.WithTimeout(ctx, s.cfg.PreflightTimeout)
	defer cancel()

	target := s.proxy.URL(index, ianaTLDsURL)
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, target, nil)
	if err != nil {
		return finish(CheckFail, err.Error())
	}
	req.Header.Set("User-Agent", userAgent())
	resp, err := s.preflightClient.Do(req)
	if err != nil {
		return finish(CheckFail, err.Error())
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return finish(CheckFail, err.Error())
	}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		if len(body) == 0 {
			return finish(CheckFail, "HTTP 200 with empty body")
		}
		return finish(CheckOK, fmt.Sprintf("HTTP %d, %d bytes", resp.StatusCode, len(body)))
	case resp.StatusCode == http.StatusUnauthorized ||
		resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusTooManyRequests:
		return finish(CheckWarn, fmt.Sprintf("HTTP %d (blocked/limited)", resp.StatusCode))
	default:
		return finish(CheckFail, fmt.Sprintf("HTTP %d", resp.StatusCode))
	}
}

func (s *Scanner) checkRDAP(
	ctx context.Context,
	base string,
) (CheckStatus, string, time.Duration) {
	if cached, ok := s.cache.GetCheck(kindRDAP, base); ok {
		return CheckStatus(cached.Status), cached.Detail + " (cached)", cached.Latency
	}
	start := time.Now()
	finish := func(status CheckStatus, detail string) (CheckStatus, string, time.Duration) {
		latency := time.Since(start)
		s.cache.PutCheck(kindRDAP, base, string(status), detail, latency)
		return status, detail, latency
	}

	urls := s.proxy.sequence(base)
	var lastErr string
	for attempt := 0; attempt < min(2, len(urls)); attempt++ {
		requestCtx, cancel := context.WithTimeout(ctx, s.cfg.PreflightTimeout)
		req, err := http.NewRequestWithContext(
			requestCtx, http.MethodGet, urls[attempt], nil,
		)
		if err != nil {
			cancel()
			return finish(CheckFail, err.Error())
		}
		req.Header.Set("User-Agent", userAgent())
		req.Header.Set("Accept", "application/rdap+json, application/json")
		resp, err := s.preflightClient.Do(req)
		if err != nil {
			cancel()
			lastErr = err.Error()
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		cancel()

		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return finish(CheckOK, fmt.Sprintf("HTTP %d", resp.StatusCode))
		case resp.StatusCode == http.StatusUnauthorized ||
			resp.StatusCode == http.StatusForbidden ||
			resp.StatusCode == http.StatusTooManyRequests:
			return finish(CheckWarn, fmt.Sprintf("HTTP %d (blocked/limited)", resp.StatusCode))
		case resp.StatusCode == http.StatusBadRequest ||
			resp.StatusCode == http.StatusNotFound ||
			resp.StatusCode == http.StatusMethodNotAllowed:
			return finish(CheckOK, fmt.Sprintf("HTTP %d", resp.StatusCode))
		case resp.StatusCode >= 500:
			lastErr = fmt.Sprintf("HTTP %d", resp.StatusCode)
			continue
		default:
			return finish(CheckOK, fmt.Sprintf("HTTP %d", resp.StatusCode))
		}
	}
	if lastErr == "" {
		lastErr = "unreachable"
	}
	return finish(CheckFail, lastErr)
}

func (s *Scanner) checkWHOIS(
	ctx context.Context,
	tld string,
) (CheckStatus, string, time.Duration) {
	server := s.whois.ServerFor(ctx, tld)
	if server == "" {
		return CheckFail, "no WHOIS server", 0
	}
	if cached, ok := s.cache.GetCheck(kindWHOIS, server); ok {
		return CheckStatus(cached.Status), cached.Detail + " (cached)", cached.Latency
	}

	start := time.Now()
	dialer := net.Dialer{Timeout: s.cfg.PreflightTimeout}
	conn, err := dialer.DialContext(
		ctx, "tcp", net.JoinHostPort(server, "43"),
	)
	latency := time.Since(start)
	if err != nil {
		detail := fmt.Sprintf("%s: %v", server, err)
		s.cache.PutCheck(kindWHOIS, server, string(CheckFail), detail, latency)
		return CheckFail, detail, latency
	}
	conn.Close()
	s.cache.PutCheck(kindWHOIS, server, string(CheckOK), server, latency)
	return CheckOK, server, latency
}

func SummarizeChecks(checks []CheckResult) PreflightSummary {
	summary := PreflightSummary{Total: len(checks)}
	for _, check := range checks {
		switch check.Status {
		case CheckOK:
			summary.OK++
		case CheckWarn:
			summary.Warn++
		case CheckFail:
			summary.Fail++
		case CheckSkip:
			summary.Skip++
		}
	}
	return summary
}

// CachedResults returns up to limit cached available domains that match the
// current TLD, length, and charset filters. --skip-cache disables this.
func (s *Scanner) CachedResults(limit int) []Result {
	if s.cfg.SkipCache {
		return nil
	}
	rows := s.cache.AvailableDomains()
	if len(rows) == 0 {
		return nil
	}
	start, _ := s.levelRange()
	var results []Result
	for _, result := range rows {
		tld := s.matchingTLD(result.Domain)
		if tld == "" {
			continue
		}
		label := strings.TrimSuffix(result.Domain, "."+tld)
		total := len(label) + len(tld)
		if len(label) < s.cfg.MinLabel || len(label) > maxDNSLabel {
			continue
		}
		if total < start || total > s.cfg.MaxLen {
			continue
		}
		if !validLabel(label, s.cfg.Alphabet) {
			continue
		}
		if s.cfg.Sequential != "" {
			if len(label) <= len(s.cfg.Sequential) ||
				!strings.HasPrefix(label, s.cfg.Sequential) {
				continue
			}
		}
		result.Length = total
		results = append(results, result)
		if len(results) >= limit {
			break
		}
	}
	return results
}

func (s *Scanner) matchingTLD(domain string) string {
	best := ""
	for _, tld := range s.tlds {
		if strings.HasSuffix(domain, "."+tld) && len(tld) > len(best) {
			best = tld
		}
	}
	return best
}

func validLabel(label, alphabet string) bool {
	if label == "" {
		return false
	}
	for i := 0; i < len(label); i++ {
		if strings.IndexByte(alphabet, label[i]) < 0 {
			return false
		}
	}
	if strings.ContainsRune(alphabet, '-') &&
		(label[0] == '-' || label[len(label)-1] == '-') {
		return false
	}
	return true
}

func (s *Scanner) Scan(ctx context.Context) (*Summary, error) {
	started := time.Now()
	stopProgress := s.startProgress(ctx, started)
	defer stopProgress()

	// Return cached available domains first. If they already fill the limit,
	// no network checks are needed at all.
	for _, result := range s.CachedResults(s.cfg.Limit) {
		s.mu.Lock()
		if len(s.found) >= s.cfg.Limit {
			s.mu.Unlock()
			break
		}
		s.found = append(s.found, result)
		s.foundSet[result.Domain] = struct{}{}
		s.mu.Unlock()
		s.stats.Checked.Add(1)
		s.stats.CacheHits.Add(1)
		s.stats.Available.Add(1)
		s.emit.Send(Event{Type: EventFound, Result: result})
	}
	if s.foundCount() >= s.cfg.Limit {
		s.setStopReason("cached results")
		return s.buildSummary(started), nil
	}

	s.scanLevels(ctx)
	summary := s.buildSummary(started)
	return summary, nil
}

// Search checks one exact label against every selected TLD. It does not
// generate labels and does not stop after -limit: every target is checked.
func (s *Scanner) Search(ctx context.Context) (*Summary, error) {
	started := time.Now()
	stopProgress := s.startProgress(ctx, started)
	defer stopProgress()

	jobs := make(chan string, s.cfg.Concurrency*2)
	go func() {
		defer close(jobs)
		for _, tld := range s.tlds {
			domain := s.cfg.Search + "." + tld
			select {
			case jobs <- domain:
			case <-ctx.Done():
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < s.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range jobs {
				s.processSearch(ctx, domain)
			}
		}()
	}
	wg.Wait()

	if ctx.Err() != nil {
		s.setStopReason("interrupted")
	} else {
		s.setStopReason("search complete")
	}
	return s.buildSearchSummary(started), nil
}

func (s *Scanner) processSearch(ctx context.Context, domain string) {
	if ctx.Err() != nil {
		return
	}
	if cached, ok := s.cache.GetDomain(domain); ok {
		s.stats.Checked.Add(1)
		s.stats.CacheHits.Add(1)
		switch cached.Status {
		case "taken":
			s.stats.Taken.Add(1)
		case "available":
			s.recordSearchAvailable(cached)
		}
		return
	}

	s.stats.Active.Add(1)
	result := s.checkDomain(ctx, domain)
	s.stats.Active.Add(-1)
	s.stats.Checked.Add(1)

	switch result.Status {
	case "taken":
		s.stats.Taken.Add(1)
	case "unknown":
		if ctx.Err() != nil {
			s.stats.Canceled.Add(1)
			return
		}
		s.stats.Unknown.Add(1)
		if s.cfg.Verbose {
			s.emit.Logf(LogWarn, "%s %s: %s",
				result.Domain, result.Method, result.Detail)
		}
	case "available":
		s.cache.PutDomain(result)
		s.recordSearchAvailable(result)
	}
}

func (s *Scanner) recordSearchAvailable(result Result) {
	s.mu.Lock()
	if _, exists := s.foundSet[result.Domain]; exists {
		s.mu.Unlock()
		return
	}
	s.found = append(s.found, result)
	s.foundSet[result.Domain] = struct{}{}
	s.mu.Unlock()

	s.stats.Available.Add(1)
	s.emit.Send(Event{Type: EventFound, Result: result})
	if result.Method == "dns" && !result.Cached {
		s.emit.Logf(LogWarn, "%s is DNS-only (unverified)", result.Domain)
	}
}

func (s *Scanner) buildSearchSummary(started time.Time) *Summary {
	return &Summary{
		Mode:        "search",
		SearchLabel: s.cfg.Search,
		SearchTotal: len(s.tlds),
		Plan:        s.Plan(),
		Results:     s.Results(),
		Stats:       s.stats.Snapshot(),
		Elapsed:     time.Since(started),
		StopReason:  s.stopReasonValue(),
	}
}

func (s *Scanner) scanLevels(ctx context.Context) {
	start, end := s.levelRange()
	for level := start; level <= end; level++ {
		if ctx.Err() != nil {
			s.setStopReason("interrupted")
			return
		}
		if s.stats.Checked.Load() >= int64(s.cfg.MaxChecks) {
			s.setStopReason("max checks reached")
			return
		}
		s.level.Store(int64(level))
		s.emit.Logf(LogInfo, "scanning length %d", level)

		before := s.foundCount()
		s.scanLevel(ctx, level)
		if ctx.Err() != nil {
			s.setStopReason("interrupted")
			return
		}
		if s.stats.Checked.Load() >= int64(s.cfg.MaxChecks) {
			s.setStopReason("max checks reached")
			return
		}
		if s.foundCount() > before {
			if s.stopReasonValue() == "" {
				s.setStopReason("shortest length found")
			}
			return
		}
	}
	s.setStopReason("search space exhausted")
}

func (s *Scanner) scanLevel(parent context.Context, level int) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	streams := newDomainStreams(level, s.tlds, &s.cfg, s.rng)
	jobs := make(chan string, s.cfg.Concurrency*4)

	go func() {
		defer close(jobs)
		for {
			domain, ok := streams.next()
			if !ok {
				return
			}
			select {
			case jobs <- domain:
			case <-ctx.Done():
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < s.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range jobs {
				s.process(ctx, domain, cancel)
			}
		}()
	}
	wg.Wait()
}

func (s *Scanner) process(
	ctx context.Context,
	domain string,
	cancel context.CancelFunc,
) {
	if ctx.Err() != nil {
		return
	}

	// Cached results are instant. Check them before the network cap so a
	// repeat run can return previously found available domains immediately.
	if cached, ok := s.cache.GetDomain(domain); ok {
		checked := s.stats.Checked.Add(1)
		s.stats.CacheHits.Add(1)
		s.verboseProgress(checked)
		switch cached.Status {
		case "taken":
			s.stats.Taken.Add(1)
		case "available":
			s.handleAvailable(ctx, cached, cancel)
		}
		return
	}

	if s.stats.Checked.Load() >= int64(s.cfg.MaxChecks) {
		s.setStopReason("max checks reached")
		cancel()
		return
	}

	s.stats.Active.Add(1)
	result := s.checkDomain(ctx, domain)
	s.stats.Active.Add(-1)
	checked := s.stats.Checked.Add(1)
	s.verboseProgress(checked)

	switch result.Status {
	case "taken":
		s.stats.Taken.Add(1)
	case "unknown":
		if ctx.Err() != nil {
			s.stats.Canceled.Add(1)
			return
		}
		s.stats.Unknown.Add(1)
		if s.cfg.Verbose {
			s.emit.Logf(LogWarn, "%s %s: %s",
				result.Domain, result.Method, result.Detail)
		}
	case "available":
		s.cache.PutDomain(result)
		s.handleAvailable(ctx, result, cancel)
	}
}

func (s *Scanner) handleAvailable(
	ctx context.Context,
	result Result,
	cancel context.CancelFunc,
) {
	s.mu.Lock()
	if _, exists := s.foundSet[result.Domain]; exists {
		s.mu.Unlock()
		return
	}
	if ctx.Err() != nil || len(s.found) >= s.cfg.Limit {
		s.mu.Unlock()
		cancel()
		return
	}
	s.found = append(s.found, result)
	s.foundSet[result.Domain] = struct{}{}
	count := len(s.found)
	s.mu.Unlock()

	s.stats.Available.Add(1)
	s.emit.Send(Event{Type: EventFound, Result: result})
	if result.Method == "dns" && !result.Cached {
		s.emit.Logf(LogWarn, "%s is DNS-only (unverified)", result.Domain)
	}
	if count >= s.cfg.Limit {
		s.setStopReason("limit reached")
		cancel()
	}
}

func (s *Scanner) checkDomain(ctx context.Context, domain string) Result {
	length := len(strings.ReplaceAll(domain, ".", ""))
	s.stats.DNSQueries.Add(1)
	status, detail := s.dns.probe(ctx, domain)

	switch status {
	case "taken":
		result := Result{
			Domain: domain, Length: length, Status: "taken",
			Method: "dns", Detail: detail,
		}
		s.cache.PutDomain(result)
		return result
	case "unknown":
		return Result{
			Domain: domain, Length: length, Status: "unknown",
			Method: "dns", Detail: detail,
		}
	}

	// DNS says the name does not exist. Confirm at the registry, because some
	// registered names are simply not delegated (they still answer NXDOMAIN).
	dot := strings.LastIndexByte(domain, '.')
	tld := domain[dot+1:]

	if !s.cfg.NoRDAP {
		if base, ok := s.rdapMap[tld]; ok {
			status, detail = s.rdap.probe(ctx, domain, base)
			switch status {
			case "taken":
				result := Result{
					Domain: domain, Length: length, Status: "taken",
					Method: "rdap", Detail: detail,
				}
				s.cache.PutDomain(result)
				return result
			case "available":
				return Result{
					Domain: domain, Length: length, Status: "available",
					Method: "rdap",
				}
			}
			if s.cfg.Verbose {
				s.emit.Logf(LogWarn, "%s: RDAP %s; trying WHOIS", domain, detail)
			}
		}
	}

	if !s.cfg.NoWHOIS {
		status, detail = s.whois.probe(ctx, domain)
		switch status {
		case "taken":
			result := Result{
				Domain: domain, Length: length, Status: "taken",
				Method: "whois", Detail: detail,
			}
			s.cache.PutDomain(result)
			return result
		case "available":
			return Result{
				Domain: domain, Length: length, Status: "available",
				Method: "whois",
			}
		default:
			return Result{
				Domain: domain, Length: length, Status: "unknown",
				Method: "whois", Detail: detail,
			}
		}
	}

	return Result{
		Domain: domain, Length: length, Status: "available",
		Method: "dns", Detail: "unverified",
	}
}

func (s *Scanner) searchTotal() int {
	if s.cfg.Search == "" {
		return 0
	}
	return len(s.tlds)
}

func (s *Scanner) startProgress(ctx context.Context, started time.Time) func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		var lastChecked int64
		var lastTime = time.Now()
		var rate float64
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case now := <-ticker.C:
				checked := s.stats.Checked.Load()
				dt := now.Sub(lastTime).Seconds()
				if dt > 0 {
					instant := float64(checked-lastChecked) / dt
					rate = 0.7*rate + 0.3*instant
				}
				lastChecked = checked
				lastTime = now
				s.emit.TrySend(Event{
					Type: EventProgress,
					Progress: Progress{
						Level:        int(s.level.Load()),
						Checked:      checked,
						MaxChecks:    s.cfg.MaxChecks,
						Found:        int64(s.foundCount()),
						Limit:        s.cfg.Limit,
						Total:        s.searchTotal(),
						Taken:        s.stats.Taken.Load(),
						Unknown:      s.stats.Unknown.Load(),
						Canceled:     s.stats.Canceled.Load(),
						CacheHits:    s.stats.CacheHits.Load(),
						DNSQueries:   s.stats.DNSQueries.Load(),
						RDAPQueries:  s.stats.RDAPQueries.Load(),
						WHOISQueries: s.stats.WHOISQueries.Load(),
						Active:       s.stats.Active.Load(),
						Elapsed:      time.Since(started),
						Rate:         rate,
					},
				})
			}
		}
	}()
	return func() { close(done) }
}

func (s *Scanner) verboseProgress(checked int64) {
	if s.cfg.Verbose && checked%1000 == 0 {
		s.emit.Logf(LogInfo, "%d checked, %d found",
			checked, s.foundCount())
	}
}

func (s *Scanner) buildSummary(started time.Time) *Summary {
	results := s.Results()
	shortest := 0
	if len(results) > 0 {
		shortest = results[0].Length
		for _, result := range results[1:] {
			if result.Length < shortest {
				shortest = result.Length
			}
		}
	}
	return &Summary{
		Mode:       "scan",
		Plan:       s.Plan(),
		Results:    results,
		Shortest:   shortest,
		Stats:      s.stats.Snapshot(),
		Elapsed:    time.Since(started),
		StopReason: s.stopReasonValue(),
	}
}

func (s *Scanner) Results() []Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Result(nil), s.found...)
}

func (s *Scanner) foundCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.found)
}

func (s *Scanner) setStopReason(reason string) {
	s.mu.Lock()
	if s.stopReason == "" {
		s.stopReason = reason
	}
	s.mu.Unlock()
}

func (s *Scanner) stopReasonValue() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopReason
}

func (s *Scanner) levelRange() (int, int) {
	minTLD := len(s.tlds[0])
	for _, tld := range s.tlds[1:] {
		if len(tld) < minTLD {
			minTLD = len(tld)
		}
	}
	return s.cfg.MinLabel + minTLD, s.cfg.MaxLen
}

func (s *Scanner) WriteOutputs() error {
	results := s.Results()
	if s.cfg.BestPrice {
		SortByRenewal(results)
	}
	return writeOutputs(results, s.cfg.JSONPath, s.cfg.CSVPath)
}

func (s *Scanner) ListTLDs(w io.Writer) {
	for _, tld := range s.tlds {
		method := "whois/dns"
		if _, ok := s.rdapMap[tld]; ok {
			method = "rdap"
		}
		fmt.Fprintf(w, "%s\t%s\n", tld, method)
	}
}

func (s *Scanner) DryRun(w io.Writer) {
	if s.cfg.Search != "" {
		s.dryRunSearch(w)
		return
	}
	start, end := s.levelRange()
	plan := s.Plan()
	fmt.Fprintf(w, "tldr-scanner %s\n", buildinfo.Version)
	fmt.Fprintf(w, "TLDs: %d selected (%d with RDAP, %d WHOIS/DNS)\n",
		plan.TLDCount, plan.RDAPCount, plan.WHOISCount)
	fmt.Fprintf(w, "Length range: %d..%d characters (label + TLD, dot excluded)\n",
		start, end)
	if s.proxy.Enabled() {
		fmt.Fprintf(w, "HTTP: %d proxy endpoints from %s\n",
			s.proxy.Len(), s.cfg.ProxyFile)
	} else {
		fmt.Fprintln(w, "HTTP: direct (no proxy file)")
	}
	fmt.Fprintf(w, "Stop after: %d available, %d checks max, %d concurrent lookups\n",
		s.cfg.Limit, s.cfg.MaxChecks, s.cfg.Concurrency)
	fmt.Fprintf(w, "Seed: %d\n", s.cfg.Seed)
	if s.cfg.Sequential != "" {
		fmt.Fprintf(w, "Sequential prefix: %s\n", s.cfg.Sequential)
	}

	total := new(big.Int)
	base := big.NewInt(int64(len(s.cfg.Alphabet)))
	fmt.Fprintln(w, "\nCandidate space per length:")
	for level := start; level <= end; level++ {
		count := new(big.Int)
		for _, tld := range s.tlds {
			labelLength := level - len(tld)
			if labelLength < s.cfg.MinLabel || labelLength > maxDNSLabel {
				continue
			}
			n := new(big.Int).Exp(base, big.NewInt(int64(labelLength)), nil)
			count.Add(count, n)
		}
		total.Add(total, count)
		fmt.Fprintf(w, "  length %d: %s candidates\n", level, count)
	}
	fmt.Fprintf(w, "  total up to length %d: %s\n", end, total)
	fmt.Fprintf(w, "\nThe scan stops after %d available domains or %d checks, so it "+
		"normally touches only a small random slice of that space.\n",
		s.cfg.Limit, s.cfg.MaxChecks)
}

func (s *Scanner) dryRunSearch(w io.Writer) {
	plan := s.Plan()
	fmt.Fprintf(w, "tldr-scanner %s\n", buildinfo.Version)
	if plan.TLDsExplicit {
		fmt.Fprintf(w, "Search: %s across %d selected TLDs\n",
			s.cfg.Search, plan.SearchTotal)
	} else {
		fmt.Fprintf(w, "Search: %s across %d TLDs (max TLD length %d)\n",
			s.cfg.Search, plan.SearchTotal, s.cfg.MaxTLDLen)
	}
	fmt.Fprintf(w, "Targets: %d domains, %d concurrent lookups\n",
		plan.SearchTotal, s.cfg.Concurrency)
	if s.proxy.Enabled() {
		fmt.Fprintf(w, "HTTP: %d proxy endpoints from %s\n",
			s.proxy.Len(), s.cfg.ProxyFile)
	} else {
		fmt.Fprintln(w, "HTTP: direct (no proxy file)")
	}
	fmt.Fprintf(w, "Seed: %d\n", s.cfg.Seed)
	if len(s.tlds) > 0 {
		fmt.Fprintln(w, "\nExample targets:")
		for i, tld := range s.tlds {
			if i >= 10 {
				fmt.Fprintf(w, "  ... and %d more\n", len(s.tlds)-i)
				break
			}
			fmt.Fprintf(w, "  %s.%s\n", s.cfg.Search, tld)
		}
	}
}

func validateSequentialPrefix(prefix string, tlds []string, maxLen int) error {
	maxLabel := 0
	for _, tld := range tlds {
		if length := maxLen - len(tld); length > maxLabel {
			maxLabel = length
		}
	}
	if len(prefix) >= maxLabel {
		return fmt.Errorf(
			"-sequential prefix %q is too long: prefix length (%d) must be "+
				"less than the label length (max %d for the selected TLDs)",
			prefix, len(prefix), maxLabel)
	}
	return nil
}

func selectTLDs(allTLDs []string, cfg *Config) ([]string, error) {
	known := make(map[string]struct{}, len(allTLDs))
	for _, tld := range allTLDs {
		known[tld] = struct{}{}
	}

	var selected []string
	if cfg.Search != "" && cfg.TLDsRaw == "" {
		for _, tld := range allTLDs {
			if len(tld) <= cfg.MaxTLDLen {
				selected = append(selected, tld)
			}
		}
	} else if cfg.TLDsRaw != "" {
		for _, part := range strings.Split(cfg.TLDsRaw, ",") {
			tld := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(part), "."))
			if tld == "" {
				continue
			}
			if _, ok := known[tld]; !ok {
				fmt.Fprintf(os.Stderr, "warning: not in the IANA root zone: %s\n", tld)
			}
			selected = append(selected, tld)
		}
	} else {
		lengths := make(map[int]struct{}, len(cfg.TLDLengths))
		for _, length := range cfg.TLDLengths {
			lengths[length] = struct{}{}
		}
		for _, tld := range allTLDs {
			if _, ok := lengths[len(tld)]; ok {
				selected = append(selected, tld)
			}
		}
	}

	excluded := make(map[string]struct{})
	for _, part := range strings.Split(cfg.ExcludeRaw, ",") {
		tld := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(part), "."))
		if tld != "" {
			excluded[tld] = struct{}{}
		}
	}

	seen := make(map[string]struct{}, len(selected))
	result := make([]string, 0, len(selected))
	for _, tld := range selected {
		if _, skip := excluded[tld]; skip {
			continue
		}
		if _, dup := seen[tld]; dup {
			continue
		}
		seen[tld] = struct{}{}
		result = append(result, tld)
	}
	if len(result) == 0 {
		if cfg.Search != "" && cfg.TLDsRaw == "" {
			return nil, fmt.Errorf(
				"no TLDs with length <= %d; increase -max-tld-len",
				cfg.MaxTLDLen)
		}
		return nil, fmt.Errorf("no TLDs selected")
	}
	return result, nil
}
