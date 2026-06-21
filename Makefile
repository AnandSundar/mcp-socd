# mcp-socd Makefile
#
# Cross-platform via Git Bash on Windows / make on Linux / macOS.
# Targets:
#   make build              - produce bin/mcp-socd static binary
#   make test               - run go test ./...
#   make test-integration   - run framework integration tests (tagged; U10)
#   make test-dist          - run goreleaser distribution tests (tagged; U11)
#   make lint               - run go vet and gofmt -l
#   make snapshot           - goreleaser build --snapshot --clean (no publish)
#   make release            - goreleaser release --clean (publishes; tag-only)
#   make install            - copy bin/mcp-socd into $(go env GOPATH)/bin
#   make tidy               - go mod tidy
#   make clean              - remove bin/, dist/, coverage artifacts
#   make version            - print the version string

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

.PHONY: all build test test-integration test-dist lint snapshot release install tidy clean version

all: build

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o $(BIN_DIR)/$(BINARY) ./cmd/mcp-socd
	@echo "built $(BIN_DIR)/$(BINARY) ($(VERSION), commit $(COMMIT))"

test:
	go test $(PKG) -count=1

# U10: framework integration tests are gated behind the `integration`
# build tag so they don't run on every developer `go test ./...`.
test-integration:
	go test -tags=integration ./test/integration/... -count=1

# U11: goreleaser pipeline tests are gated behind the `dist` build tag
# so they don't run without goreleaser installed.
test-dist:
	go test -tags=dist ./dist/... -count=1

lint:
	@echo "==> gofmt"
	@gofmt -l . | tee /tmp/gofmt-issues.txt | [ ! -s /tmp/gofmt-issues.txt ]
	@echo "==> go vet"
	@go vet $(PKG)

snapshot:
	goreleaser build --snapshot --clean

# Tag-only: running `make release` locally will publish to GitHub. The
# CI workflow (.github/workflows/release.yml) is the intended entry point.
release:
	goreleaser release --clean

install: build
	@GOBIN=$$(go env GOPATH)/bin; \
	mkdir -p "$$GOBIN"; \
	cp $(BIN_DIR)/$(BINARY) "$$GOBIN/$(BINARY)"; \
	echo "installed $$GOBIN/$(BINARY)"

tidy:
	go mod tidy

clean:
	rm -rf $(BIN_DIR) dist/ coverage.html coverage.txt

version:
	@echo "$(VERSION) ($(COMMIT), $(DATE))"