package scanner

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type DNSResolver struct {
	servers []string
	timeout time.Duration
	next    atomic.Uint64
}

func newDNSResolver(timeout time.Duration) *DNSResolver {
	servers := []string{"1.1.1.1:53", "8.8.8.8:53"}
	if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cfg.Servers) > 0 {
		port := cfg.Port
		if port == "" {
			port = "53"
		}
		servers = make([]string, 0, len(cfg.Servers))
		for _, server := range cfg.Servers {
			servers = append(servers, net.JoinHostPort(server, port))
		}
	}
	return &DNSResolver{servers: servers, timeout: timeout}
}

// probe returns free / taken / unknown using an NS lookup. NXDOMAIN means the
// name does not exist; NOERROR with no NS means it exists but is undelegated.
func (r *DNSResolver) probe(ctx context.Context, domain string) (string, string) {
	var lastErr string
	for attempt := 0; attempt < 2; attempt++ {
		server := r.servers[int(r.next.Add(1)-1)%len(r.servers)]
		resp, err := r.exchange(ctx, server, domain, "udp")
		if err != nil {
			lastErr = err.Error()
			continue
		}
		if resp.Truncated {
			resp, err = r.exchange(ctx, server, domain, "tcp")
			if err != nil {
				lastErr = err.Error()
				continue
			}
		}

		switch resp.Rcode {
		case dns.RcodeNameError:
			return "free", ""
		case dns.RcodeSuccess:
			for _, answer := range resp.Answer {
				if _, ok := answer.(*dns.NS); ok {
					return "taken", "NS present"
				}
			}
			// NOERROR without an NS record: registered but undelegated.
			return "taken", "no NS"
		case dns.RcodeServerFailure, dns.RcodeRefused:
			lastErr = "DNS " + dns.RcodeToString[resp.Rcode]
			continue
		default:
			return "unknown", "DNS " + dns.RcodeToString[resp.Rcode]
		}
	}
	if lastErr == "" {
		lastErr = "DNS timeout"
	}
	return "unknown", lastErr
}

func (r *DNSResolver) exchange(
	ctx context.Context,
	server, domain, network string,
) (*dns.Msg, error) {
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	message.RecursionDesired = true

	client := &dns.Client{Timeout: r.timeout, Net: network}
	resp, _, err := client.ExchangeContext(ctx, message, server)
	if err != nil {
		return nil, fmt.Errorf("DNS %s: %w", network, err)
	}
	if resp == nil {
		return nil, fmt.Errorf("DNS %s: empty response", network)
	}
	return resp, nil
}
