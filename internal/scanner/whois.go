package scanner

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

var freeWHOISMarkers = []string{
	"no match",
	"not found",
	"no data found",
	"no entries found",
	"not registered",
	"available for registration",
	"is available",
	"domain is free",
	"no object found",
	"nothing found",
	"does not exist",
	"no information available",
	"status: free",
	"no matching record",
	"no record found",
	"domain not registered",
}

var takenWHOISMarkers = []string{
	"domain name:",
	"registry domain id",
	"creation date",
	"registrar:",
	"registrant:",
	"domain status:",
	"name server:",
	"nameserver:",
	"registry expiry date",
	"holder:",
	"admin-c:",
	"tech-c:",
	"status: active",
}

type WHOISClient struct {
	timeout time.Duration
	delay   time.Duration
	sems    *keyedSemaphores
	stats   *Stats
	cache   *Cache

	mu       sync.Mutex
	servers  map[string]string
	failures map[string]int
}

func newWHOISClient(
	timeout, delay time.Duration,
	stats *Stats,
	cache *Cache,
) *WHOISClient {
	return &WHOISClient{
		timeout:  timeout,
		delay:    delay,
		sems:     newKeyedSemaphores(),
		stats:    stats,
		cache:    cache,
		servers:  make(map[string]string),
		failures: make(map[string]int),
	}
}

func (w *WHOISClient) probe(ctx context.Context, domain string) (string, string) {
	dot := strings.LastIndexByte(domain, '.')
	if dot < 0 {
		return "unknown", "invalid domain"
	}
	server := w.ServerFor(ctx, domain[dot+1:])
	if server == "" {
		return "unknown", "no WHOIS server"
	}
	if w.failureCount(server) >= 3 {
		return "unknown", "WHOIS host disabled after repeated failures"
	}

	sem := w.sems.get(server, 1)
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return "unknown", "canceled"
	}
	text, err := whoisQuery(ctx, server, domain, w.timeout)
	if w.delay > 0 {
		sleepCtx(ctx, w.delay)
	}
	<-sem
	if err != nil {
		w.recordFailure(server)
		return "unknown", err.Error()
	}

	w.stats.WHOISQueries.Add(1)
	return parseWHOIS(text)
}

// ServerFor discovers (and caches) the WHOIS server for a TLD. An empty string
// means discovery failed or the TLD has no usable WHOIS server.
func (w *WHOISClient) ServerFor(ctx context.Context, tld string) string {
	if w.cache != nil {
		if cached, ok := w.cache.GetCheck(kindWHOISDiscovery, tld); ok {
			if cached.Status == string(CheckOK) {
				return cached.Detail
			}
			return ""
		}
	}

	w.mu.Lock()
	server, ok := w.servers[tld]
	w.mu.Unlock()
	if ok {
		return server
	}

	sem := w.sems.get(whoisIANA, 1)
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return ""
	}
	text, err := whoisQuery(ctx, whoisIANA, tld, w.timeout)
	<-sem

	server = ""
	if err == nil {
		server = parseWhoisServer(text)
	}
	w.mu.Lock()
	w.servers[tld] = server
	w.mu.Unlock()
	if w.cache != nil {
		status := string(CheckFail)
		if server != "" {
			status = string(CheckOK)
		}
		w.cache.PutCheck(kindWHOISDiscovery, tld, status, server, 0)
	}
	return server
}

func (w *WHOISClient) failureCount(server string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.failures[server]
}

func (w *WHOISClient) recordFailure(server string) {
	w.mu.Lock()
	w.failures[server]++
	w.mu.Unlock()
}

func parseWhoisServer(text string) string {
	for _, line := range strings.Split(text, "\n") {
		lower := strings.ToLower(line)
		if !strings.HasPrefix(lower, "whois:") {
			continue
		}
		server := strings.TrimSpace(line[len("whois:"):])
		if server != "" && !strings.EqualFold(server, whoisIANA) {
			return server
		}
	}
	return ""
}

func parseWHOIS(text string) (string, string) {
	lowered := strings.ToLower(text)
	head := lowered
	if len(head) > 2000 {
		head = head[:2000]
	}
	for _, marker := range freeWHOISMarkers {
		if strings.Contains(head, marker) {
			return "available", ""
		}
	}
	for _, marker := range takenWHOISMarkers {
		if strings.Contains(lowered, marker) {
			return "taken", ""
		}
	}
	if strings.Contains(lowered, "rate limit") ||
		strings.Contains(lowered, "exceeded") ||
		strings.Contains(lowered, "quota") {
		return "unknown", "rate limited"
	}
	return "unknown", "unrecognized reply"
}

func whoisQuery(
	ctx context.Context,
	server, query string,
	timeout time.Duration,
) (string, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(server, "43"))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	if _, err := io.WriteString(conn, query+"\r\n"); err != nil {
		return "", err
	}
	data, err := io.ReadAll(io.LimitReader(conn, 256<<10))
	if err != nil {
		return "", fmt.Errorf("WHOIS read: %w", err)
	}
	return string(data), nil
}
