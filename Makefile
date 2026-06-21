# mcp-socd Makefile
#
# Cross-platform via Git Bash on Windows. Targets:
#   make build       - produce bin/mcp-socd static binary
#   make test        - run go test ./...
#   make lint        - run go vet and gofmt -l
#   make tidy        - go mod tidy
#   make clean       - remove bin/ and coverage artifacts
#   make version     - print the version string

BINARY      := mcp-socd
BIN_DIR     := bin
PKG         := ./...
VERSION_PKG := mcp-socd/internal/version

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Deferred (=) so VERSION/COMMIT/DATE are expanded at recipe time, not at
# assignment time (which would be too early for `?=` to have fired).
LDFLAGS = -ldflags "-s -w -X $(VERSION_PKG).Version=$(VERSION) -X $(VERSION_PKG).Commit=$(COMMIT) -X $(VERSION_PKG).BuildDate=$(DATE)"

.PHONY: all build test lint tidy clean version

all: build

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o $(BIN_DIR)/$(BINARY) ./cmd/mcp-socd
	@echo "built $(BIN_DIR)/$(BINARY) ($(VERSION), commit $(COMMIT))"

test:
	go test $(PKG) -count=1

lint:
	@echo "==> gofmt"
	@gofmt -l . | tee /tmp/gofmt-issues.txt | [ ! -s /tmp/gofmt-issues.txt ]
	@echo "==> go vet"
	@go vet $(PKG)

tidy:
	go mod tidy

clean:
	rm -rf $(BIN_DIR) coverage.html coverage.txt

version:
	@echo "$(VERSION) ($(COMMIT), $(DATE))"
