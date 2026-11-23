package buildinfo

import (
	"fmt"
	"runtime"
	"strings"
)

// These values are overridden at build time with -ldflags -X.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

func Full() string {
	parts := []string{Version}
	if Commit != "" && Commit != "unknown" {
		parts = append(parts, Commit)
	}
	if Date != "" && Date != "unknown" {
		parts = append(parts, Date)
	}
	return strings.Join(parts, " ")
}

func Platform() string {
	return fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
}
