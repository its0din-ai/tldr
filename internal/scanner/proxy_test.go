package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadProxyFile(t *testing.T) {
	content := `# comment
https://worker-1.example.workers.dev

URL: https://worker-2.example.workers.dev
https://worker-3.example.workers.dev/?url={url}
https://worker-4.example.workers.dev/base?token=x
1. node
Status: Active
`
	path := filepath.Join(t.TempDir(), "proxylist.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadProxyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"https://worker-1.example.workers.dev?url={url}",
		"https://worker-2.example.workers.dev?url={url}",
		"https://worker-3.example.workers.dev/?url={url}",
		"https://worker-4.example.workers.dev/base?token=x&url={url}",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d proxies, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("proxy %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLoadProxyFileEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(path, []byte("# nothing here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProxyFile(path); err == nil {
		t.Fatal("expected an error for an empty proxy file")
	}
}

func TestProxyPoolURL(t *testing.T) {
	pool := NewProxyPool([]string{
		"https://a.example/?url={url}",
		"https://b.example/?url={url}",
	})
	target := "https://rdap.example/domain/abc.fm?x=1"
	want := "https://a.example/?url=https%3A%2F%2Frdap.example%2Fdomain%2Fabc.fm%3Fx%3D1"
	if got := pool.URL(0, target); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	sequence := pool.sequence(target)
	if len(sequence) != 2 {
		t.Fatalf("got %d sequence entries, want 2", len(sequence))
	}
	if sequence[0] != pool.URL(0, target) || sequence[1] != pool.URL(1, target) {
		t.Errorf("unexpected sequence: %v", sequence)
	}
}

func TestSafeProxyName(t *testing.T) {
	if got := SafeProxyName("https://user:pass@worker.example/?url={url}"); got != "worker.example" {
		t.Errorf("got %q, want worker.example", got)
	}
}
