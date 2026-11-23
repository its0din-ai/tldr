package scanner

import (
	"path/filepath"
	"testing"
)

func TestDefaultDataDir(t *testing.T) {
	t.Setenv("TLDR_DATA_DIR", "/tmp/tldr-data-override")
	if got := DefaultDataDir(); got != "/tmp/tldr-data-override" {
		t.Errorf("TLDR_DATA_DIR: got %q", got)
	}

	t.Setenv("TLDR_DATA_DIR", "")
	t.Setenv("XDG_DATA_HOME", "/tmp/tldr-xdg")
	if got := DefaultDataDir(); got != filepath.Join("/tmp/tldr-xdg", "tldr-scanner") {
		t.Errorf("XDG_DATA_HOME: got %q", got)
	}

	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", "/tmp/tldr-home")
	if got := DefaultDataDir(); got != "/tmp/tldr-home/.local/share/tldr-scanner" {
		t.Errorf("HOME fallback: got %q", got)
	}
}
