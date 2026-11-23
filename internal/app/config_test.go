package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseAlphabet(t *testing.T) {
	got, err := parseAlphabet("letters")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 26 || got[0] != 'a' || got[25] != 'z' {
		t.Errorf("letters alphabet = %q", got)
	}

	if _, err := parseAlphabet("a_z"); err == nil {
		t.Error("expected an error for an invalid character")
	}
	if _, err := parseAlphabet(""); err == nil {
		t.Error("expected an error for an empty charset")
	}

	got, err = parseAlphabet("abca")
	if err != nil {
		t.Fatal(err)
	}
	if got != "abc" {
		t.Errorf("deduplicated alphabet = %q, want abc", got)
	}
}

func TestParseFlagsDefaults(t *testing.T) {
	parsed, err := ParseFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := parsed.Config
	if cfg.MinLabel != 3 || cfg.MaxLen != 5 || cfg.Limit != 10 {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
	if len(cfg.TLDLengths) != 1 || cfg.TLDLengths[0] != 2 {
		t.Errorf("unexpected TLD lengths: %v", cfg.TLDLengths)
	}
	if cfg.ProxyFile != "" || len(cfg.Proxies) != 0 {
		t.Errorf("expected no proxies by default")
	}
	if cfg.Alphabet != "abcdefghijklmnopqrstuvwxyz" {
		t.Errorf("unexpected alphabet: %q", cfg.Alphabet)
	}
}

func TestParseSequentialPrefix(t *testing.T) {
	letters := "abcdefghijklmnopqrstuvwxyz"
	got, err := parseSequentialPrefix("AA", letters)
	if err != nil {
		t.Fatal(err)
	}
	if got != "aa" {
		t.Errorf("prefix = %q, want aa", got)
	}
	if _, err := parseSequentialPrefix("a1", letters); err == nil {
		t.Error("expected digits to be rejected with a letters charset")
	}
	got, err = parseSequentialPrefix("a1", letters+"0123456789")
	if err != nil {
		t.Fatal(err)
	}
	if got != "a1" {
		t.Errorf("prefix = %q, want a1", got)
	}

	parsed, err := ParseFlags([]string{"-sequential", "aa"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Config.Sequential != "aa" {
		t.Errorf("parsed prefix = %q, want aa", parsed.Config.Sequential)
	}
}

func TestParseSearchLabel(t *testing.T) {
	tests := []struct {
		input string
		want  string
		ok    bool
	}{
		{"gnu", "gnu", true},
		{"GNU", "gnu", true},
		{"my-name2", "my-name2", true},
		{"gnu.fi", "", false},
		{"-gnu", "", false},
		{"gnu-", "", false},
		{"a_b", "", false},
		{"", "", false},
	}
	for _, test := range tests {
		got, err := parseSearchLabel(test.input)
		if test.ok && err != nil {
			t.Errorf("parseSearchLabel(%q) error: %v", test.input, err)
		}
		if !test.ok && err == nil {
			t.Errorf("parseSearchLabel(%q) expected an error", test.input)
		}
		if got != test.want {
			t.Errorf("parseSearchLabel(%q) = %q, want %q",
				test.input, got, test.want)
		}
	}
}

func TestParseFlagsProxyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxylist.txt")
	content := "https://worker-one.example.workers.dev\n" +
		"https://worker-two.example.workers.dev\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseFlags([]string{"-proxyfile", path, "-tlds", "fm"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Config.ProxyFile != path {
		t.Errorf("proxy file = %q, want %q", parsed.Config.ProxyFile, path)
	}
	if len(parsed.Config.Proxies) != 2 {
		t.Errorf("got %d proxies, want 2", len(parsed.Config.Proxies))
	}
}

func TestDataDirDefaults(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "tldr-data")
	t.Setenv("TLDR_DATA_DIR", dataDir)

	parsed, err := ParseFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Config.DataDir != dataDir {
		t.Errorf("data dir = %q, want %q", parsed.Config.DataDir, dataDir)
	}
	wantCache := filepath.Join(dataDir, "tldr-scanner.db")
	if parsed.Config.CachePath != wantCache {
		t.Errorf("cache path = %q, want %q", parsed.Config.CachePath, wantCache)
	}
}

func TestDataDirFlagMovesCache(t *testing.T) {
	t.Setenv("TLDR_DATA_DIR", filepath.Join(t.TempDir(), "ignored"))
	dataDir := filepath.Join(t.TempDir(), "custom-data")

	parsed, err := ParseFlags([]string{"-data-dir", dataDir})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Config.DataDir != dataDir {
		t.Errorf("data dir = %q, want %q", parsed.Config.DataDir, dataDir)
	}
	if want := filepath.Join(dataDir, "tldr-scanner.db"); parsed.Config.CachePath != want {
		t.Errorf("cache path = %q, want %q", parsed.Config.CachePath, want)
	}
}

func TestExplicitCachePathWins(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	cachePath := filepath.Join(t.TempDir(), "custom.db")
	parsed, err := ParseFlags([]string{
		"-data-dir", dataDir,
		"-cache", cachePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Config.CachePath != cachePath {
		t.Errorf("cache path = %q, want %q", parsed.Config.CachePath, cachePath)
	}
}
