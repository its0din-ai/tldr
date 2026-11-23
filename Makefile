BINARY := tldr
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X github.com/its0din-ai/tldr/internal/buildinfo.Version=$(VERSION) \
	-X github.com/its0din-ai/tldr/internal/buildinfo.Commit=$(COMMIT) \
	-X github.com/its0din-ai/tldr/internal/buildinfo.Date=$(DATE)

.PHONY: build test vet fmt clean

build:
	mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) .

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

clean:
	rm -rf bin
