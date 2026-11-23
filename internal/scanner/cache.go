package scanner

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	connectivityTTL = 48 * time.Hour
	availableTTL    = 48 * time.Hour
	priceTTL        = 24 * time.Hour

	kindDNS            = "dns"
	kindProxy          = "proxy"
	kindRDAP           = "rdap"
	kindWHOIS          = "whois"
	kindWHOISDiscovery = "whois-discovery"
)

type CachedCheck struct {
	Status  string
	Detail  string
	Latency time.Duration
}

// Cache is a local SQLite cache for checked domains, connectivity checks, and
// discovered WHOIS servers. Available domains are cached for 48 hours so a
// repeat run can return them without any network checks.
type Cache struct {
	db        *sql.DB
	takenTTL  time.Duration
	disabled  bool
	skipReads bool
}

func NewCache(
	path string,
	takenTTL time.Duration,
	skipReads bool,
) (*Cache, error) {
	if path == "" {
		return &Cache{takenTTL: takenTTL, disabled: true}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// One connection keeps writes serialized and avoids SQLITE_BUSY.
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", pragma, err)
		}
	}
	schema := `
CREATE TABLE IF NOT EXISTS domains (
    domain     TEXT PRIMARY KEY,
    status     TEXT NOT NULL,
    method     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    checked_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS connectivity (
    kind       TEXT NOT NULL,
    target     TEXT NOT NULL,
    status     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    latency_ms INTEGER NOT NULL DEFAULT 0,
    checked_at INTEGER NOT NULL,
    PRIMARY KEY (kind, target)
);
CREATE TABLE IF NOT EXISTS prices (
    tld                    TEXT PRIMARY KEY,
    registration           REAL NOT NULL,
    renewal                REAL NOT NULL,
    currency               TEXT NOT NULL,
    registration_registrar TEXT NOT NULL DEFAULT '',
    renewal_registrar      TEXT NOT NULL DEFAULT '',
    source                 TEXT NOT NULL DEFAULT '',
    checked_at             INTEGER NOT NULL
);
CREATE VIEW IF NOT EXISTS available_with_prices AS
SELECT d.domain, d.method, d.checked_at,
       p.tld, p.registration, p.renewal, p.currency,
       p.registration_registrar, p.renewal_registrar,
       p.source AS price_source, p.checked_at AS price_checked_at
  FROM domains d
  LEFT JOIN prices p ON d.domain LIKE '%.' || p.tld
 WHERE d.status = 'available';
`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	maxTTL := takenTTL
	if availableTTL > maxTTL {
		maxTTL = availableTTL
	}
	if _, err := db.Exec(
		"DELETE FROM domains WHERE checked_at < ?",
		time.Now().Add(-maxTTL).Unix(),
	); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(
		"DELETE FROM connectivity WHERE checked_at < ?",
		time.Now().Add(-connectivityTTL).Unix(),
	); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(
		"DELETE FROM prices WHERE checked_at < ?",
		time.Now().Add(-7*24*time.Hour).Unix(),
	); err != nil {
		db.Close()
		return nil, err
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		_ = os.Chmod(path+suffix, 0o600)
	}
	return &Cache{
		db:        db,
		takenTTL:  takenTTL,
		skipReads: skipReads,
	}, nil
}

func (c *Cache) Close() error {
	if c == nil || c.disabled || c.db == nil {
		return nil
	}
	return c.db.Close()
}

// GetDomain returns a fresh cached domain result. Available and taken results
// are cached; unknown results are never stored.
func (c *Cache) GetDomain(domain string) (Result, bool) {
	if c == nil || c.disabled || c.skipReads || c.db == nil {
		return Result{}, false
	}
	var (
		status    string
		method    string
		detail    string
		checkedAt int64
	)
	err := c.db.QueryRow(
		`SELECT status, method, detail, checked_at FROM domains WHERE domain = ?`,
		domain,
	).Scan(&status, &method, &detail, &checkedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Result{}, false
	}
	if err != nil {
		return Result{}, false
	}

	ttl := c.takenTTL
	if status == "available" {
		ttl = availableTTL
	}
	if time.Since(time.Unix(checkedAt, 0)) > ttl {
		return Result{}, false
	}
	return Result{
		Domain: domain,
		Length: len(strings.ReplaceAll(domain, ".", "")),
		Status: status,
		Method: method,
		Detail: detail,
		Cached: true,
	}, true
}

func (c *Cache) PutDomain(result Result) {
	if c == nil || c.disabled || c.db == nil {
		return
	}
	if result.Status != "available" && result.Status != "taken" {
		return
	}
	_, _ = c.db.Exec(
		`INSERT INTO domains (domain, status, method, detail, checked_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(domain) DO UPDATE SET
		     status = excluded.status,
		     method = excluded.method,
		     detail = excluded.detail,
		     checked_at = excluded.checked_at`,
		result.Domain,
		result.Status,
		result.Method,
		result.Detail,
		time.Now().Unix(),
	)
}

// AvailableDomains returns all cached available domains younger than 48 hours,
// newest first. The scanner applies the current TLD/label filters.
func (c *Cache) AvailableDomains() []Result {
	if c == nil || c.disabled || c.skipReads || c.db == nil {
		return nil
	}
	rows, err := c.db.Query(
		`SELECT domain, method, detail
		   FROM domains
		  WHERE status = 'available' AND checked_at >= ?
		  ORDER BY checked_at DESC
		  LIMIT 10000`,
		time.Now().Add(-availableTTL).Unix(),
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var results []Result
	for rows.Next() {
		var domain, method, detail string
		if err := rows.Scan(&domain, &method, &detail); err != nil {
			continue
		}
		results = append(results, Result{
			Domain: domain,
			Length: len(strings.ReplaceAll(domain, ".", "")),
			Status: "available",
			Method: method,
			Detail: detail,
			Cached: true,
		})
	}
	return results
}

// GetCheck returns a cached connectivity result younger than 48 hours.
func (c *Cache) GetCheck(kind, target string) (CachedCheck, bool) {
	if c == nil || c.disabled || c.skipReads || c.db == nil {
		return CachedCheck{}, false
	}
	var (
		status    string
		detail    string
		latencyMs int64
		checkedAt int64
	)
	err := c.db.QueryRow(
		`SELECT status, detail, latency_ms, checked_at
		   FROM connectivity WHERE kind = ? AND target = ?`,
		kind, target,
	).Scan(&status, &detail, &latencyMs, &checkedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return CachedCheck{}, false
	}
	if err != nil {
		return CachedCheck{}, false
	}
	if time.Since(time.Unix(checkedAt, 0)) > connectivityTTL {
		return CachedCheck{}, false
	}
	return CachedCheck{
		Status:  status,
		Detail:  detail,
		Latency: time.Duration(latencyMs) * time.Millisecond,
	}, true
}

func (c *Cache) PutCheck(
	kind, target, status, detail string,
	latency time.Duration,
) {
	if c == nil || c.disabled || c.db == nil {
		return
	}
	_, _ = c.db.Exec(
		`INSERT INTO connectivity
		     (kind, target, status, detail, latency_ms, checked_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(kind, target) DO UPDATE SET
		     status = excluded.status,
		     detail = excluded.detail,
		     latency_ms = excluded.latency_ms,
		     checked_at = excluded.checked_at`,
		kind, target, status, detail, latency.Milliseconds(), time.Now().Unix(),
	)
}

// GetPrice returns a cached tld-list price younger than 24 hours.
func (c *Cache) GetPrice(tld string) (*Price, bool) {
	if c == nil || c.disabled || c.skipReads || c.db == nil {
		return nil, false
	}
	var (
		registration          float64
		renewal               float64
		currency              string
		registrationRegistrar string
		renewalRegistrar      string
		source                string
		checkedAt             int64
	)
	err := c.db.QueryRow(
		`SELECT registration, renewal, currency,
		        registration_registrar, renewal_registrar, source, checked_at
		   FROM prices WHERE tld = ?`, tld,
	).Scan(
		&registration, &renewal, &currency,
		&registrationRegistrar, &renewalRegistrar, &source, &checkedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false
	}
	if err != nil {
		return nil, false
	}
	if time.Since(time.Unix(checkedAt, 0)) > priceTTL {
		return nil, false
	}
	return &Price{
		Registration:          registration,
		Renewal:               renewal,
		Currency:              currency,
		RegistrationRegistrar: registrationRegistrar,
		RenewalRegistrar:      renewalRegistrar,
		Source:                source,
	}, true
}

func (c *Cache) PutPrice(tld string, price *Price) {
	if c == nil || c.disabled || c.db == nil || price == nil {
		return
	}
	_, _ = c.db.Exec(
		`INSERT INTO prices
		     (tld, registration, renewal, currency,
		      registration_registrar, renewal_registrar, source, checked_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(tld) DO UPDATE SET
		     registration = excluded.registration,
		     renewal = excluded.renewal,
		     currency = excluded.currency,
		     registration_registrar = excluded.registration_registrar,
		     renewal_registrar = excluded.renewal_registrar,
		     source = excluded.source,
		     checked_at = excluded.checked_at`,
		tld, price.Registration, price.Renewal, price.Currency,
		price.RegistrationRegistrar, price.RenewalRegistrar,
		price.Source, time.Now().Unix(),
	)
}
