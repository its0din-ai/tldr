# tldr-scanner

Find the shortest domains that are still **unregistered**, prioritizing the
shortest TLDs. For example, it can look for 5-character names such as
`hek.nz` or `gnu.fi` (label + TLD, dot excluded).

Free data sources only:

1. [IANA TLD list](https://data.iana.org/TLD/) — which TLDs exist.
2. [IANA RDAP bootstrap](https://data.iana.org/rdap/dns.json) — each TLD's
   authoritative RDAP server.
3. DNS `NS` lookup — cheap pre-filter.
4. RDAP — registry data; HTTP 404 means the name is not registered.
5. WHOIS — fallback for TLDs that do not publish RDAP (e.g. `.io`, `.gg`, `.me`).

## Features

- **TUI by default** when stdin/stdout are a terminal: it always shows whether
  the scanner is loading, checking connectivity, scanning, finished, or stopped.
- **Connectivity preflight** for DNS, each proxy, each RDAP registry, and each
  WHOIS server, with per-endpoint latency and failures.
- **Clear scan progress**: found/limit, checked count, rate, in-flight network
  requests, elapsed time, and the final stop reason.
- **Search mode**: check one exact label (e.g. `gnu`) across every TLD up to
  `-max-tld-len`, and list every available TLD.
- **Price enrichment** with `-best-price`: cheapest registration and renewal
  from tld-list.com, cached in SQLite.
- **Optional FlareProx support** via a gitignored `proxylist.txt`.
- **SQLite cache** in `.data/`: available domains and connectivity checks for
  48 hours, taken domains for 7 days.
- Linux `amd64`/`arm64` binaries built by GitHub Actions.

## Install

Requirements: Go 1.24 or newer.

```bash
git clone https://github.com/its0din-ai/tldr.git
cd tldr
make build          # -> bin/tldr
./bin/tldr -version
```

Or install directly:

```bash
go install github.com/its0din-ai/tldr@latest
```

## Usage

```bash
# Shortest (2-letter) TLDs, 5-character domains, stop after 10 hits
./bin/tldr

# Pick the TLDs yourself
./bin/tldr -tlds fm,to,gg -limit 20

# Ignore cached checks/results and refresh everything
./bin/tldr -tlds fm -skip-cache

# Search one label across all 2-letter TLDs
./bin/tldr -search gnu

# Include 3-letter TLDs too (.com, .net, ...)
./bin/tldr -search gnu -max-tld-len 3

# Restrict a search to explicit TLDs (overrides -max-tld-len)
./bin/tldr -search gnu -tlds com,net,gg,fi,id

# Add cheapest registration/renewal prices from tld-list.com
./bin/tldr -search gnu -best-price

# Allow 4-character domains too (2-letter label + 2-letter TLD)
./bin/tldr -min-label 2

# Also consider 3-letter TLDs (6-character domains)
./bin/tldr -tld-lens 2,3 -max-len 6

# Sequential prefix: aaa, aab, aac, ... (use -max-len 6 for aaab, aaac, ...)
./bin/tldr -sequential aa -max-len 6

# Preview the search space without querying anything
./bin/tldr -dry-run -tlds fm

# Non-interactive output (also used automatically when stdout is not a TTY)
./bin/tldr -no-tui -tlds fm

# Save results
./bin/tldr -tlds fm -json results.jsonl -csv results.csv
```

## Search mode

`-search` checks one exact label against every selected TLD instead of
generating random labels:

```bash
# 248 two-letter TLDs
./bin/tldr -search gnu

# 2- and 3-letter TLDs: 464 targets, including .com and .net
./bin/tldr -search gnu -max-tld-len 3
```

- `-max-tld-len` defaults to `2`; `3` includes `.com`, `.net`, and every other
  three-letter TLD from the IANA root zone.
- `-tlds` overrides `-max-tld-len` when both are provided.
- `-limit`, `-min-label`, `-max-len`, `-charset`, `-sequential`, and
  `-tld-lens` do not apply in search mode.
- Every target TLD is checked; all available domains are reported.
- Hits appear live in the TUI (`SEARCHING`, checked/TLDs, available list) or as
  individual lines with `-no-tui`.
- `-skip-cache` forces a fresh check of every target.
- `-dry-run` prints the target list instead of querying.

For a large first-time search, `-skip-preflight` avoids waiting for the
connectivity phase; unavailable endpoints show up as `unknown` in the results.

## The TUI: is it working or stopped?

The header always shows the current phase and a live spinner:

```
tldr-scanner dev                                    CONNECTING ⠋
TLDs 248 (74 RDAP / 174 WHOIS) · length 5..5 · limit 10 · 2 proxies · seed 42

Connectivity checks — distinct from scanning; network latency here is expected.
[████████░░░░░░░░░░░░░░░░░░] 12/247 ⠋
  ✓ proxy  proxy #1 worker...      180ms  HTTP 200, 9512 bytes
  ✓ dns    system resolver           1ms  NS present
  ✓ rdap   rdap.centralnic.com      948ms  HTTP 200
  ! whois  gg                      1.5s   whois.gg (cached)
  …
```

Once connectivity checks finish:

```
tldr-scanner dev                                      SCANNING ⠸

Found 3 / 10  [███████░░░░░░░░░░░░░░░░░]
  length 5 · checked 1,234 / 100,000 max · 42.0/s · active 8 · elapsed 12s
  taken 900 · unknown 12 · canceled 8 · cache 40
  connectivity: 46 ok · 1 warn · 1 failed
```

- A moving spinner means the process is alive.
- In `-search` mode the badge is **SEARCHING** and progress is shown as
  `checked N / total TLDs`; the found list shows each available TLD.
- With `-best-price`, a **PRICING** phase shows per-TLD price fetches before
  the final report.
- `active N` is the number of in-flight DNS/RDAP/WHOIS requests.
- If the rate drops, the TUI says `waiting on N network request(s) — endpoint
  latency, not a stalled scan`.
- When done, it shows `DONE (<reason>)`, e.g. `limit reached`,
  `max checks reached`, `search space exhausted`, or `interrupted`.
- The **CONNECTING** phase is separate from scanning. Slow connectivity checks
  are endpoint/network latency, not a stuck scan. Use `-skip-preflight` to go
  straight to scanning.

The TUI uses the alternate screen; when you quit, the final report is printed
to the normal terminal.

## Sequential prefix

`-sequential` takes a prefix, not a boolean. The prefix stays fixed while the
remaining label characters are generated:

```bash
# label length 3: aaa, aab, aac, ...
# label length 4: aaaa, aaab, aaac, ...
./bin/tldr -sequential aa
```

- The prefix must be shorter than the label length for at least one selected
  TLD. If it is too long, the command fails with an explanatory error.
- The maximum label length is `-max-len` minus the TLD length. For example,
  with `-max-len 5` and a 2-letter TLD, the maximum label length is 3, so a
  2-character prefix is the longest valid prefix and `-sequential aa` produces
  only `aaa` .. `aaz`. Use `-max-len 6` to also reach `aaab`, `aaac`, ...
- Prefix characters must be in `-charset` (default `letters`). Use
  `-charset alnum` if the prefix contains digits.
- Search mode ignores `-sequential`.

## Connectivity preflight

Before scanning, `tldr-scanner` checks:

- the system DNS resolver,
- every proxy endpoint,
- every distinct RDAP registry base URL,
- every WHOIS server (discovered through `whois.iana.org`).

Results are stored in the local SQLite cache and reused for **48 hours**:

- DNS resolver checks
- proxy endpoint checks
- RDAP endpoint checks
- WHOIS server checks and WHOIS server discovery

Flags:

```bash
-skip-preflight          # skip all connectivity checks
-require-preflight       # abort if any check fails
-preflight-concurrency 12
-preflight-timeout 4     # seconds per endpoint
-skip-cache              # ignore cached values; refresh the DB with fresh results
```

A large default TLD set can produce hundreds of checks on the first run. That
is expected and visible in the TUI; subsequent runs reuse the SQLite cache.

## Prices (`-best-price`)

`-best-price` enriches available results with the cheapest registration and
renewal prices from [tld-list.com](https://tld-list.com/). It works with
`-search` and with normal shortest-domain scans:

```bash
./bin/tldr -search gnu -best-price
./bin/tldr -search gnu -max-tld-len 3 -best-price
```

Example output (sorted by lowest renewal):

```
Available domains for gnu:
  DOMAIN                 LEN  METHOD       REG     RENEW
  gnu.id                   5  rdap      $11.03    $15.99
  gnu.ac                   5  whois     $24.64    $26.06
```

With `-best-price`, final results are sorted by **cheapest renewal**, then
cheapest registration, then domain. Results without a known renewal price go
last. This applies to the terminal table, TUI results, JSONL, and CSV.

Prices are stored per TLD in `.data/tldr-scanner.db` and reused for **24
hours**. The database has an `available_with_prices` view for easy queries:

```sql
SELECT * FROM available_with_prices;
```

### Price sources

1. **tld-list API** when keys are configured:
   ```bash
   export TLD_LIST_PUBLIC_KEY=...
   export TLD_LIST_PRIVATE_KEY=...
   # or:
   ./bin/tldr -search gnu -best-price \
     -tldlist-public-key ... -tldlist-private-key ...
   ```
   The API is documented at
   [tld-list.com/docs-api](https://tld-list.com/docs-api).
2. **Public tld-list pages** (`https://tld-list.com/tld/<tld>`), parsed from
   their JSON-LD price data. The scanner uses a direct system `curl` request
   first because it passes Cloudflare more reliably than a plain Go HTTP
   client; if `curl` is unavailable or fails, the Go client uses your
   `--proxyfile` endpoints and then a direct fallback.

Some networks and hosted proxies are challenged by Cloudflare and return
`HTTP 403`. If you see that, install `curl`, use the API keys above, or use a
network that can reach tld-list directly. The official API is preferred where
possible; prices are cached to be polite. Prices are standard TLD prices from
tld-list.com; premium names and registrar-specific promos can differ.

## SQLite cache

Cache data is stored in `.data/`:

- `.data/tldr-scanner.db` — SQLite database (gitignored)
- `.data/tlds.txt`, `.data/rdap.json` — bootstrap files

The database stores:

- **available domains** for 48 hours, so a repeat run can return them instantly
  without DNS/RDAP/WHOIS checks (shown as `(cached)`),
- **taken domains** for 7 days (configurable with `-cache-ttl`),
- **connectivity checks** for 48 hours,
- **WHOIS server discovery** for 48 hours,
- **tld-list prices** for 24 hours (when `-best-price` is used).

If cached available domains already fill `-limit`, the scanner returns them
immediately and skips both connectivity checks and scanning:

```
DONE (cached results) · 5 checked · 0s
  found 5 · taken 0 · unknown 0 · canceled 0 · cache 5
  queries: DNS 0, RDAP 0, WHOIS 0
```

```bash
# Use a different database path
./bin/tldr -cache /tmp/tldr.db

# Ignore cached values and refresh the database
./bin/tldr -skip-cache
```

`-no-cache` remains as a deprecated alias for `-skip-cache`. Cached values are
ignored while fresh check results are still written back to the database.

## Proxies (FlareProx)

Proxies are **not** hardcoded. Copy the example and add your own endpoints:

```bash
cp proxylist.example.txt proxylist.txt
# add endpoints from `python3 flareprox.py list`
./bin/tldr --proxyfile proxylist.txt
```

`proxylist.txt` is gitignored. Accepted formats, one per line:

```
https://my-worker-1.my-subdomain.workers.dev
https://my-worker-2.my-subdomain.workers.dev
URL: https://my-worker-3.my-subdomain.workers.dev
https://my-worker-4.my-subdomain.workers.dev/?url={url}
```

Base URLs (the normal [FlareProx](https://github.com/MrTurvey/flareprox)
format) are expanded to `?url={url}` automatically. Full templates containing
`{url}` are used as-is. Comments start with `#`. The endpoints are used
round-robin with per-request failover.

## How it works

For each total length, starting at the shortest possible
(`min_label + len(tld)`):

0. First return cached available domains that match the current filters.
1. Generate labels in random order, or as `prefix + suffix` with
   `-sequential <prefix>`.
2. Ask DNS for `NS`. A name that resolves is clearly registered, so skip it.
3. If DNS says the name does not exist, confirm at the registry via RDAP
   (a `404` means unregistered) or WHOIS for TLDs without RDAP.
4. Stop as soon as `-limit` available domains are found at that length.

The random order means each run explores a different slice of the space.
Cached available domains are returned immediately (marked `(cached)`) so you
can retrieve previous hits quickly. Taken domains are cached for 7 days.
Use `-skip-cache` to force fresh network checks for everything.

Labels shorter than 3 characters are excluded by default because registries
almost universally reserve 1- and 2-character names.

## Caveats

- **Unregistered does not mean registrable.** Registries reserve short labels,
  flag premium names, and some ccTLDs require local presence or a business ID.
  Always confirm at a registrar before assuming a name can be bought.
- A DNS-only result (`-no-rdap -no-whois`) is a hint, not proof. The default
  two-step check avoids undelegated-but-registered false positives.
- Available domains are reported at the shortest length found, but not
  exhaustively: the scan stops after `-limit` hits. All hits are the same
  length, so one is not "shorter" than another.
- Registry RDAP/WHOIS servers rate-limit or throttle bulk queries. Keep
  `-concurrency` and `-rdap-per-host` modest, and respect each registry's
  terms of use. WHOIS is serialized per host on purpose.
- Brand TLDs, restricted ccTLDs, and premium pricing are not detected.
  Use `-tlds` to target extensions you can actually register.
- Cached available domains are not re-verified for 48 hours. If you need a
  fresh result (for example, before registering), use `-skip-cache`.

## Why not the tld-list.com API?

[tld-list.com](https://tld-list.com/) has a legacy API at
`https://api.tld-list.com/v1` (POST + public/private key pair). It exposes TLD
and registrar **pricing** methods (`extension/get`, `extension/getNames`,
`extension/getCheapestRegistrar`, `registrar/getIds`) with a limit of 100
requests per 15 minutes. It does **not** expose domain availability, which is
why this scanner uses RDAP and WHOIS directly.

## Project layout

```
main.go                  CLI entry point
internal/app/            flag parsing, orchestration, plain output
internal/scanner/        bootstrap, DNS/RDAP/WHOIS, preflight, prices, SQLite cache, scan
internal/tui/            Bubble Tea TUI
internal/buildinfo/      version metadata (ldflags)
.github/workflows/       linux amd64/arm64 build and release workflow
proxylist.example.txt    committed proxy example
proxylist.txt            local proxy list (gitignored)
.data/                   local SQLite DB and bootstrap files (gitignored)
```

## Development

```bash
make test
make vet
make build
```

The GitHub Actions workflow runs tests, builds
`tldr-linux-amd64` and `tldr-linux-arm64`, uploads them as
artifacts, and attaches both binaries plus `SHA256SUMS.txt` to a release when
a `v*` tag is pushed.

The project is named **tldr-scanner**; the installed command is `tldr`.
