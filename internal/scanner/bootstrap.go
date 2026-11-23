package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func fetchViaProxies(
	ctx context.Context,
	client *http.Client,
	pool *ProxyPool,
	target string,
) ([]byte, error) {
	urls := pool.sequence(target)
	attempts := max(2, len(urls))
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		req, err := http.NewRequestWithContext(
			ctx, http.MethodGet, urls[attempt%len(urls)], nil,
		)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", userAgent())

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("HTTP %d from proxy", resp.StatusCode)
			continue
		}

		head := bytes.TrimSpace(body)
		if len(head) > 300 {
			head = head[:300]
		}
		head = bytes.ToLower(head)
		if bytes.HasPrefix(head, []byte("<!doctype html")) ||
			bytes.HasPrefix(head, []byte("<html")) {
			lastErr = fmt.Errorf("proxy returned an HTML page")
			continue
		}
		return body, nil
	}
	return nil, fmt.Errorf("could not fetch %s: %w", target, lastErr)
}

func fetchCached(
	ctx context.Context,
	client *http.Client,
	pool *ProxyPool,
	target string,
	path string,
	ttl time.Duration,
) ([]byte, error) {
	if info, err := os.Stat(path); err == nil && time.Since(info.ModTime()) < ttl {
		if data, err := os.ReadFile(path); err == nil {
			return data, nil
		}
	}

	data, err := fetchViaProxies(ctx, client, pool, target)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return data, nil
}

func loadTLDs(
	ctx context.Context,
	client *http.Client,
	pool *ProxyPool,
	dir string,
) ([]string, error) {
	raw, err := fetchCached(
		ctx, client, pool, ianaTLDsURL, filepath.Join(dir, "tlds.txt"), bootstrapTTL,
	)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !isASCII(line) || strings.HasPrefix(line, "xn--") {
			continue
		}
		seen[line] = struct{}{}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("IANA TLD list came back empty; delete %s and retry", dir)
	}

	tlds := make([]string, 0, len(seen))
	for tld := range seen {
		tlds = append(tlds, tld)
	}
	sort.Strings(tlds)
	return tlds, nil
}

func loadRDAPMap(
	ctx context.Context,
	client *http.Client,
	pool *ProxyPool,
	dir string,
) (map[string]string, error) {
	raw, err := fetchCached(
		ctx, client, pool, ianaRDAPURL, filepath.Join(dir, "rdap.json"), bootstrapTTL,
	)
	if err != nil {
		return nil, err
	}

	var bootstrap struct {
		Services [][2]json.RawMessage `json:"services"`
	}
	if err := json.Unmarshal(raw, &bootstrap); err != nil {
		return nil, fmt.Errorf(
			"IANA RDAP bootstrap is not valid JSON; delete %s and retry: %w", dir, err,
		)
	}

	result := make(map[string]string)
	for _, service := range bootstrap.Services {
		var tlds, urls []string
		if json.Unmarshal(service[0], &tlds) != nil ||
			json.Unmarshal(service[1], &urls) != nil {
			continue
		}
		base := ""
		for _, candidate := range urls {
			if strings.HasPrefix(candidate, "https://") {
				base = candidate
				break
			}
		}
		if base == "" && len(urls) > 0 {
			base = urls[0]
		}
		if base == "" {
			continue
		}
		base = strings.TrimRight(base, "/") + "/"
		for _, tld := range tlds {
			result[strings.ToLower(tld)] = base
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("IANA RDAP bootstrap contained no services")
	}
	return result, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}
