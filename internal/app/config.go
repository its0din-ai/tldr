package app

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/its0din-ai/tldr/internal/scanner"
)

type ParseResult struct {
	Config      scanner.Config
	ShowVersion bool
}

func ParseFlags(args []string) (ParseResult, error) {
	var result ParseResult
	cfg := &result.Config
	var (
		tldLensRaw       string
		timeoutSeconds   float64
		whoisDelaySecs   float64
		cacheTTLSeconds  int64
		preflightTimeout float64
		charsetRaw       string
	)

	fs := flag.NewFlagSet("tldr", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"Find the shortest available domains across the shortest TLDs.\n\n"+
				"Usage: %s [options]\n\nOptions:\n", fs.Name())
		fs.PrintDefaults()
	}

	fs.StringVar(&cfg.TLDsRaw, "tlds", "",
		"comma-separated TLDs to scan (e.g. fm,gg,io)")
	fs.StringVar(&tldLensRaw, "tld-lens", "2",
		"comma-separated TLD lengths to use when -tlds is omitted")
	fs.StringVar(&cfg.ExcludeRaw, "exclude-tlds", "",
		"comma-separated TLDs to skip")
	fs.IntVar(&cfg.MinLabel, "min-label", 3,
		"minimum label length (1-2 are usually registry-reserved)")
	fs.IntVar(&cfg.MaxLen, "max-len", 5,
		"maximum domain length excluding the dot (label + TLD)")
	fs.IntVar(&cfg.Limit, "limit", 10,
		"stop after this many available domains (ignored by -search)")
	fs.StringVar(&cfg.Search, "search", "",
		"check one exact label against every TLD up to -max-tld-len (e.g. -search gnu)")
	fs.IntVar(&cfg.MaxTLDLen, "max-tld-len", 2,
		"maximum TLD length used by -search")
	fs.StringVar(&charsetRaw, "charset", "letters",
		"letters, alnum, ldh, or an explicit substring of a-z0-9-")
	fs.StringVar(&cfg.Sequential, "sequential", "",
		"sequential label prefix, e.g. -sequential aa generates aaa, aab, ...")
	fs.Int64Var(&cfg.Seed, "seed", -1,
		"random seed (printed; default: random)")
	fs.IntVar(&cfg.Concurrency, "concurrency", 50,
		"concurrent DNS/check workers")
	fs.Float64Var(&timeoutSeconds, "timeout", 6.0,
		"per-query timeout in seconds")
	fs.IntVar(&cfg.RDAPPerHost, "rdap-per-host", 4,
		"max concurrent RDAP requests per registry")
	fs.IntVar(&cfg.MaxChecks, "max-checks", 100000,
		"hard cap on candidates checked (safety valve)")
	fs.BoolVar(&cfg.NoRDAP, "no-rdap", false,
		"skip RDAP confirmation")
	fs.BoolVar(&cfg.NoWHOIS, "no-whois", false,
		"skip WHOIS confirmation/fallback")
	fs.Float64Var(&whoisDelaySecs, "whois-delay", 0.2,
		"seconds to wait after each WHOIS query to a host")
	fs.StringVar(&cfg.CachePath, "cache", ".data/tldr-scanner.db",
		"SQLite cache path")
	fs.Int64Var(&cacheTTLSeconds, "cache-ttl", 7*86400,
		"how long a 'taken' result stays cached, in seconds")
	fs.BoolVar(&cfg.BestPrice, "best-price", false,
		"fetch cheapest registration/renewal prices from tld-list.com")
	fs.StringVar(&cfg.TLDListPublicKey, "tldlist-public-key",
		os.Getenv("TLD_LIST_PUBLIC_KEY"),
		"tld-list.com API public key (or TLD_LIST_PUBLIC_KEY)")
	fs.StringVar(&cfg.TLDListPrivateKey, "tldlist-private-key",
		os.Getenv("TLD_LIST_PRIVATE_KEY"),
		"tld-list.com API private key (or TLD_LIST_PRIVATE_KEY)")
	fs.BoolVar(&cfg.SkipCache, "skip-cache", false,
		"ignore cached values and refresh the SQLite cache with fresh results")
	fs.BoolVar(&cfg.SkipCache, "no-cache", false,
		"deprecated alias for -skip-cache")
	fs.StringVar(&cfg.JSONPath, "json", "",
		"write available results as JSONL")
	fs.StringVar(&cfg.CSVPath, "csv", "",
		"write available results as CSV")
	fs.BoolVar(&cfg.ListTLDs, "list-tlds", false,
		"print selected TLDs and exit")
	fs.BoolVar(&cfg.DryRun, "dry-run", false,
		"print the candidate space and exit without querying")
	fs.BoolVar(&cfg.Verbose, "v", false, "more logging")
	fs.BoolVar(&cfg.Verbose, "verbose", false, "more logging")
	fs.StringVar(&cfg.ProxyFile, "proxyfile", "",
		"FlareProx proxy list (one endpoint per line); no proxies when omitted")
	fs.BoolVar(&cfg.SkipPreflight, "skip-preflight", false,
		"skip DNS/proxy/RDAP/WHOIS connectivity checks")
	fs.BoolVar(&cfg.RequirePreflight, "require-preflight", false,
		"abort if any connectivity check fails")
	fs.IntVar(&cfg.PreflightConcurrency, "preflight-concurrency", 12,
		"concurrent connectivity checks")
	fs.Float64Var(&preflightTimeout, "preflight-timeout", 4.0,
		"per-endpoint connectivity check timeout in seconds")
	fs.BoolVar(&cfg.NoTUI, "no-tui", false,
		"disable the interactive TUI and print plain progress")
	fs.BoolVar(&result.ShowVersion, "version", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		return result, err
	}

	if cfg.MinLabel < 1 || cfg.MinLabel > 63 {
		return result, fmt.Errorf("-min-label must be between 1 and 63")
	}
	if cfg.MaxLen < 1 {
		return result, fmt.Errorf("-max-len must be positive")
	}
	if cfg.Limit < 1 {
		return result, fmt.Errorf("-limit must be at least 1")
	}
	if cfg.Concurrency < 1 {
		return result, fmt.Errorf("-concurrency must be at least 1")
	}
	if cfg.MaxChecks < 1 {
		return result, fmt.Errorf("-max-checks must be at least 1")
	}
	if cfg.RDAPPerHost < 1 {
		return result, fmt.Errorf("-rdap-per-host must be at least 1")
	}
	if timeoutSeconds <= 0 {
		return result, fmt.Errorf("-timeout must be positive")
	}
	if whoisDelaySecs < 0 {
		return result, fmt.Errorf("-whois-delay cannot be negative")
	}
	if cacheTTLSeconds < 0 {
		return result, fmt.Errorf("-cache-ttl cannot be negative")
	}
	if cfg.MaxTLDLen < 1 || cfg.MaxTLDLen > 63 {
		return result, fmt.Errorf("-max-tld-len must be between 1 and 63")
	}
	if cfg.BestPrice &&
		(cfg.TLDListPublicKey == "") != (cfg.TLDListPrivateKey == "") {
		fmt.Fprintln(os.Stderr,
			"warning: set both -tldlist-public-key and -tldlist-private-key; "+
				"falling back to public tld-list pages")
	}
	if cfg.Search != "" {
		label, err := parseSearchLabel(cfg.Search)
		if err != nil {
			return result, err
		}
		cfg.Search = label
		if cfg.TLDsRaw != "" {
			fmt.Fprintln(os.Stderr,
				"note: -tlds overrides -max-tld-len in search mode")
		}
	}
	if cfg.PreflightConcurrency < 1 {
		return result, fmt.Errorf("-preflight-concurrency must be at least 1")
	}
	if preflightTimeout <= 0 {
		return result, fmt.Errorf("-preflight-timeout must be positive")
	}

	cfg.Timeout = time.Duration(timeoutSeconds * float64(time.Second))
	cfg.WHOISDelay = time.Duration(whoisDelaySecs * float64(time.Second))
	cfg.CacheTTL = time.Duration(cacheTTLSeconds) * time.Second
	cfg.PreflightTimeout = time.Duration(preflightTimeout * float64(time.Second))

	for _, part := range strings.Split(tldLensRaw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		length, err := strconv.Atoi(part)
		if err != nil || length < 1 {
			return result, fmt.Errorf("-tld-lens must be comma-separated positive integers")
		}
		cfg.TLDLengths = append(cfg.TLDLengths, length)
	}
	if len(cfg.TLDLengths) == 0 {
		return result, fmt.Errorf("-tld-lens is empty")
	}

	alphabet, err := parseAlphabet(charsetRaw)
	if err != nil {
		return result, err
	}
	cfg.Alphabet = alphabet
	if cfg.Sequential != "" {
		prefix, err := parseSequentialPrefix(cfg.Sequential, alphabet)
		if err != nil {
			return result, err
		}
		cfg.Sequential = prefix
	}
	if cfg.Search != "" && cfg.Sequential != "" {
		fmt.Fprintln(os.Stderr, "note: -sequential is ignored in search mode")
	}

	if cfg.ProxyFile != "" {
		proxies, err := scanner.LoadProxyFile(cfg.ProxyFile)
		if err != nil {
			return result, err
		}
		cfg.Proxies = proxies
	}
	if cfg.Seed < 0 {
		cfg.Seed = time.Now().UnixNano()
	}
	if cfg.NoRDAP && cfg.NoWHOIS {
		fmt.Fprintln(os.Stderr,
			"warning: both RDAP and WHOIS are disabled; available results are "+
				"DNS-only and unverified")
	}
	if fs.NArg() > 0 {
		return result, fmt.Errorf("unexpected arguments: %s",
			strings.Join(fs.Args(), " "))
	}
	return result, nil
}

func parseAlphabet(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	aliases := map[string]string{
		"letters":        "abcdefghijklmnopqrstuvwxyz",
		"alpha":          "abcdefghijklmnopqrstuvwxyz",
		"alnum":          "abcdefghijklmnopqrstuvwxyz0123456789",
		"letters-digits": "abcdefghijklmnopqrstuvwxyz0123456789",
		"ldh":            "abcdefghijklmnopqrstuvwxyz0123456789-",
		"all":            "abcdefghijklmnopqrstuvwxyz0123456789-",
	}
	alphabet := value
	if expanded, ok := aliases[value]; ok {
		alphabet = expanded
	}
	seen := make(map[rune]struct{})
	var result []rune
	for _, char := range alphabet {
		if (char < 'a' || char > 'z') &&
			(char < '0' || char > '9') &&
			char != '-' {
			return "", fmt.Errorf(
				"invalid charset %q: use letters, alnum, ldh or a-z0-9- only",
				value)
		}
		if _, ok := seen[char]; ok {
			continue
		}
		seen[char] = struct{}{}
		result = append(result, char)
	}
	if len(result) == 0 {
		return "", fmt.Errorf("charset is empty")
	}
	return string(result), nil
}

func parseSearchLabel(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", fmt.Errorf("-search requires a non-empty label")
	}
	if strings.Contains(value, ".") {
		return "", fmt.Errorf("-search takes a single label, not a domain")
	}
	if len(value) > 63 {
		return "", fmt.Errorf("-search label must be 63 characters or fewer")
	}
	for i := 0; i < len(value); i++ {
		char := value[i]
		if (char < 'a' || char > 'z') &&
			(char < '0' || char > '9') &&
			char != '-' {
			return "", fmt.Errorf(
				"-search label may only contain a-z, 0-9 and internal hyphens")
		}
	}
	if value[0] == '-' || value[len(value)-1] == '-' {
		return "", fmt.Errorf("-search label cannot start or end with a hyphen")
	}
	return value, nil
}

func parseSequentialPrefix(value, alphabet string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", nil
	}
	if strings.Contains(value, ".") {
		return "", fmt.Errorf("-sequential takes a label prefix, not a domain")
	}
	if len(value) > 63 {
		return "", fmt.Errorf("-sequential prefix must be 63 characters or fewer")
	}
	for i := 0; i < len(value); i++ {
		if strings.IndexByte(alphabet, value[i]) < 0 {
			return "", fmt.Errorf(
				"-sequential prefix %q contains a character outside the charset %q",
				value, alphabet)
		}
	}
	if strings.ContainsRune(alphabet, '-') && value[0] == '-' {
		return "", fmt.Errorf("-sequential prefix cannot start with a hyphen")
	}
	return value, nil
}
