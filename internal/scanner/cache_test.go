package scanner

import (
	"path/filepath"
	"testing"
	"time"
)

func TestCacheDomains(t *testing.T) {
	cache, err := NewCache(
		filepath.Join(t.TempDir(), "cache.db"), 7*24*time.Hour, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()

	cache.PutDomain(Result{
		Domain: "abc.fm", Length: 5, Status: "available", Method: "rdap",
	})
	got, ok := cache.GetDomain("abc.fm")
	if !ok {
		t.Fatal("expected available domain in cache")
	}
	if !got.Cached || got.Status != "available" || got.Method != "rdap" {
		t.Fatalf("unexpected cached result: %+v", got)
	}

	cache.PutDomain(Result{
		Domain: "xyz.fm", Length: 5, Status: "taken", Method: "dns",
	})
	if _, ok := cache.GetDomain("xyz.fm"); !ok {
		t.Fatal("expected taken domain in cache")
	}
	if _, ok := cache.GetDomain("missing.fm"); ok {
		t.Fatal("unexpected cache hit for unknown domain")
	}

	// Available results expire after 48 hours.
	if _, err := cache.db.Exec(
		"UPDATE domains SET checked_at = ? WHERE domain = ?",
		time.Now().Add(-49*time.Hour).Unix(), "abc.fm",
	); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.GetDomain("abc.fm"); ok {
		t.Fatal("expected expired available result to be ignored")
	}
}

func TestCacheConnectivity(t *testing.T) {
	cache, err := NewCache(
		filepath.Join(t.TempDir(), "cache.db"), 7*24*time.Hour, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()

	cache.PutCheck(kindRDAP, "https://rdap.example/", "ok", "HTTP 200", 120*time.Millisecond)
	check, ok := cache.GetCheck(kindRDAP, "https://rdap.example/")
	if !ok {
		t.Fatal("expected cached connectivity check")
	}
	if check.Status != "ok" || check.Detail != "HTTP 200" ||
		check.Latency != 120*time.Millisecond {
		t.Fatalf("unexpected cached check: %+v", check)
	}

	// Connectivity checks expire after 48 hours.
	if _, err := cache.db.Exec(
		`UPDATE connectivity SET checked_at = ?
		  WHERE kind = ? AND target = ?`,
		time.Now().Add(-49*time.Hour).Unix(), kindRDAP, "https://rdap.example/",
	); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.GetCheck(kindRDAP, "https://rdap.example/"); ok {
		t.Fatal("expected expired connectivity check to be ignored")
	}
}

func TestCacheAvailableDomains(t *testing.T) {
	cache, err := NewCache(
		filepath.Join(t.TempDir(), "cache.db"), 7*24*time.Hour, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()

	cache.PutDomain(Result{Domain: "abc.fm", Status: "available", Method: "rdap"})
	cache.PutDomain(Result{Domain: "old.fm", Status: "available", Method: "rdap"})
	cache.PutDomain(Result{Domain: "taken.fm", Status: "taken", Method: "dns"})
	if _, err := cache.db.Exec(
		"UPDATE domains SET checked_at = ? WHERE domain = ?",
		time.Now().Add(-49*time.Hour).Unix(), "old.fm",
	); err != nil {
		t.Fatal(err)
	}

	results := cache.AvailableDomains()
	if len(results) != 1 || results[0].Domain != "abc.fm" {
		t.Fatalf("unexpected available domains: %+v", results)
	}
	if !results[0].Cached {
		t.Fatal("expected Cached marker")
	}
}

func TestValidLabel(t *testing.T) {
	alphabet := "abcdefghijklmnopqrstuvwxyz"
	if !validLabel("abc", alphabet) {
		t.Fatal("abc should be valid")
	}
	if validLabel("abc1", alphabet) {
		t.Fatal("abc1 should be invalid with a letters-only alphabet")
	}
	if validLabel("-abc", alphabet+"-") {
		t.Fatal("leading hyphen should be invalid")
	}
	if !validLabel("a-b", alphabet+"-") {
		t.Fatal("a-b should be valid when hyphens are allowed")
	}
}

func TestCacheSkipReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")

	first, err := NewCache(path, 7*24*time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	first.PutDomain(Result{Domain: "old.fm", Status: "available", Method: "rdap"})
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	refresh, err := NewCache(path, 7*24*time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := refresh.GetDomain("old.fm"); ok {
		t.Fatal("skip-reads cache returned an old value")
	}
	refresh.PutDomain(Result{Domain: "new.fm", Status: "available", Method: "rdap"})
	if err := refresh.Close(); err != nil {
		t.Fatal(err)
	}

	third, err := NewCache(path, 7*24*time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	if _, ok := third.GetDomain("new.fm"); !ok {
		t.Fatal("fresh result was not written back to the cache")
	}
}

func TestCacheDisabled(t *testing.T) {
	cache, err := NewCache("", 7*24*time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	cache.PutDomain(Result{Domain: "abc.fm", Status: "available", Method: "rdap"})
	if _, ok := cache.GetDomain("abc.fm"); ok {
		t.Fatal("disabled cache returned a domain")
	}
	cache.PutCheck(kindRDAP, "x", "ok", "", 0)
	if _, ok := cache.GetCheck(kindRDAP, "x"); ok {
		t.Fatal("disabled cache returned a connectivity check")
	}
}
