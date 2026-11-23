package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type RDAPClient struct {
	client  *http.Client
	proxy   *ProxyPool
	perHost int
	sems    *keyedSemaphores
	stats   *Stats
}

func newHTTPTransport() *http.Transport {
	return &http.Transport{
		// Traffic is proxied explicitly through ProxyPool, so do not also
		// honor HTTP_PROXY/HTTPS_PROXY from the environment.
		Proxy:               nil,
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}
}

func (r *RDAPClient) probe(
	ctx context.Context,
	domain, base string,
) (string, string) {
	target := base + "domain/" + domain
	proxyURLs := r.proxy.sequence(target)
	sem := r.sems.get(upstreamHost(base), r.perHost)

	var lastErr string
	for attempt := 0; attempt < 3; attempt++ {
		requestURL := proxyURLs[attempt%len(proxyURLs)]
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		req.Header.Set("User-Agent", userAgent())
		req.Header.Set("Accept", "application/rdap+json, application/json")

		resp, body, err := r.do(ctx, req, sem)
		if err != nil {
			lastErr = err.Error()
			if attempt < 2 && !sleepCtx(ctx, time.Duration(attempt+1)*500*time.Millisecond) {
				return "unknown", "canceled"
			}
			continue
		}
		r.stats.RDAPQueries.Add(1)

		contentType := strings.ToLower(resp.Header.Get("Content-Type"))
		switch {
		case resp.StatusCode == http.StatusNotFound:
			if strings.Contains(contentType, "html") {
				lastErr = "proxy returned HTML 404"
				if attempt < 2 && !sleepCtx(ctx, time.Duration(attempt+1)*500*time.Millisecond) {
					return "unknown", "canceled"
				}
				continue
			}
			return "available", ""

		case resp.StatusCode == http.StatusOK:
			if contentType != "" && !strings.Contains(contentType, "json") {
				lastErr = "non-JSON response (" + contentType + ")"
				if attempt < 2 && !sleepCtx(ctx, time.Duration(attempt+1)*500*time.Millisecond) {
					return "unknown", "canceled"
				}
				continue
			}
			var payload struct {
				ErrorCode int `json:"errorCode"`
			}
			if json.Unmarshal(body, &payload) == nil && payload.ErrorCode == 404 {
				return "available", ""
			}
			return "taken", ""

		case resp.StatusCode == http.StatusForbidden ||
			resp.StatusCode == http.StatusTooManyRequests ||
			resp.StatusCode >= 500:
			lastErr = fmt.Sprintf("HTTP %d", resp.StatusCode)
			if attempt < 2 {
				wait := retryDelay(resp.Header.Get("Retry-After"), attempt)
				if !sleepCtx(ctx, wait) {
					return "unknown", "canceled"
				}
				continue
			}
			return "unknown", lastErr

		default:
			return "unknown", fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
	}
	if lastErr == "" {
		lastErr = "RDAP retries exhausted"
	}
	return "unknown", lastErr
}

func (r *RDAPClient) do(
	ctx context.Context,
	req *http.Request,
	sem chan struct{},
) (*http.Response, []byte, error) {
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	defer func() { <-sem }()

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	if err != nil {
		return nil, nil, err
	}
	return resp, body, nil
}

func retryDelay(retryAfter string, attempt int) time.Duration {
	if seconds, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil {
		if seconds < 0 {
			seconds = 0
		}
		if seconds > 10 {
			seconds = 10
		}
		return time.Duration(seconds) * time.Second
	}
	return time.Duration(attempt+1) * 500 * time.Millisecond
}

func upstreamHost(base string) string {
	if parsed, err := url.Parse(base); err == nil && parsed.Host != "" {
		return parsed.Host
	}
	return base
}
