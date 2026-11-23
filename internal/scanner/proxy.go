package scanner

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
)

// ProxyPool wraps target URLs with FlareProx/HTTP proxy templates. Templates
// are used round-robin, and each request can fail over to the next one.
type ProxyPool struct {
	templates []string
	next      atomic.Uint64
}

func NewProxyPool(templates []string) *ProxyPool {
	return &ProxyPool{templates: append([]string(nil), templates...)}
}

func (p *ProxyPool) Enabled() bool {
	return len(p.templates) > 0
}

func (p *ProxyPool) Templates() []string {
	return p.templates
}

func (p *ProxyPool) Len() int {
	return len(p.templates)
}

// URL builds the proxied URL for a specific endpoint. index is modulo-safe.
func (p *ProxyPool) URL(index int, target string) string {
	if len(p.templates) == 0 {
		return target
	}
	template := p.templates[index%len(p.templates)]
	return strings.ReplaceAll(template, "{url}", url.QueryEscape(target))
}

// sequence returns every proxy URL for one target, starting at the next
// endpoint in the rotation. With no proxies it returns the target itself.
func (p *ProxyPool) sequence(target string) []string {
	if len(p.templates) == 0 {
		return []string{target}
	}
	count := len(p.templates)
	start := int(p.next.Add(1)-1) % count
	urls := make([]string, count)
	for offset := 0; offset < count; offset++ {
		urls[offset] = p.URL((start+offset)%count, target)
	}
	return urls
}

// LoadProxyFile reads a FlareProx-style proxy list. One endpoint per line is
// expected, but `python3 flareprox.py list` output (`URL: https://...`) and
// explicit `{url}` templates also work.
func LoadProxyFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var templates []string
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
			if line == "" {
				continue
			}
		}

		// FlareProx's `list` command prints "URL: https://...".
		if strings.HasPrefix(strings.ToUpper(line), "URL:") {
			line = strings.TrimSpace(line[len("URL:"):])
		}

		// Tolerate numbered/status lines by extracting the first URL.
		if !strings.Contains(line, "://") {
			continue
		}
		if start := strings.Index(line, "http://"); start >= 0 {
			line = line[start:]
		} else if start := strings.Index(line, "https://"); start >= 0 {
			line = line[start:]
		}
		line = strings.Fields(line)[0]

		template := line
		if !strings.Contains(template, "{url}") {
			parsed, err := url.Parse(line)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" {
				return nil, fmt.Errorf("%s:%d: invalid proxy URL %q", path, lineNumber, line)
			}
			if parsed.RawQuery != "" {
				template = line + "&url={url}"
			} else {
				template = line + "?url={url}"
			}
		}
		if _, duplicate := seen[template]; duplicate {
			continue
		}
		seen[template] = struct{}{}
		templates = append(templates, template)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(templates) == 0 {
		return nil, fmt.Errorf("no proxy endpoints found in %s", path)
	}
	return templates, nil
}

// SafeProxyName hides credentials and query strings when displaying an endpoint.
func SafeProxyName(template string) string {
	raw := strings.ReplaceAll(template, "{url}", "")
	if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
		return parsed.Host
	}
	return raw
}
