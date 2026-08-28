.PHONY: build test test-cover test-race lint vet fmt check tidy clean \
        cover-domain demo demo-live

GOBIN   = ./bin
GOFLAGS = -trimpath

# Coverage thresholds. internal/ overall must clear 90%; internal/domain
# must be at 100% (design §2.2). cmd/* is excluded from both denominators —
# the command binaries are thin wiring exercised end-to-end, not by unit tests.
COVERAGE_THRESHOLD        = 90
DOMAIN_COVERAGE_THRESHOLD = 100

# Pinned tool version. Must match the version: in .github/workflows/ci.yml —
# bump both at once. Auto-installed into $(GOBIN) on first `make lint`.
GOLANGCI_LINT_VERSION = v2.11.4
GOLANGCI_LINT         = $(GOBIN)/golangci-lint

# ─── Build ──────────────────────────────────────────────────────────

build:
	@echo "Building all packages and commands..."
	@go build $(GOFLAGS) ./...

# ─── Demo ───────────────────────────────────────────────────────────
# Offline, deterministic end-to-end tour (design §8): builds both binaries,
# boots agent-trust-discovery (no auth) on :8080 with a fresh /tmp db, hydrates it from
# fixtures/ via agent-hydrator-stub, then runs the eight-stop walkthrough.
demo:
	@echo "Building demo binaries into $(GOBIN)..."
	@go build $(GOFLAGS) -o $(GOBIN)/agent-trust-discovery ./cmd/agent-trust-discovery
	@go build $(GOFLAGS) -o $(GOBIN)/agent-hydrator-stub ./cmd/agent-hydrator-stub
	@bash scripts/demo/run-demo.sh

# Live snapshot demo (plan §4): captures fixtures from prod Search API + TL,
# then runs the unchanged hydrator/prober pipeline against the snapshot.
# The mock `make demo` path is intentionally untouched.
demo-live:
	@echo "Building live-demo binaries into $(GOBIN)..."
	@go build $(GOFLAGS) -o $(GOBIN)/agent-trust-discovery ./cmd/agent-trust-discovery
	@go build $(GOFLAGS) -o $(GOBIN)/agent-snapshot ./cmd/agent-snapshot
	@go build $(GOFLAGS) -o $(GOBIN)/agent-hydrator-stub ./cmd/agent-hydrator-stub
	@go build $(GOFLAGS) -o $(GOBIN)/agent-prober ./cmd/agent-prober
	@bash scripts/demo/run-demo-live.sh

# ─── Test ───────────────────────────────────────────────────────────

test:
	@echo "Running tests..."
	@go test ./... -count=1

test-cover:
	@echo "Running tests with coverage..."
	@pkgs=$$(go list ./... | grep -v '/cmd/' | tr '\n' ',' | sed 's/,$$//'); \
	go test ./... -count=1 -coverpkg=$$pkgs -coverprofile=coverage.out -covermode=atomic
	@go tool cover -func=coverage.out
	@echo ""
	@echo "Checking coverage threshold ($(COVERAGE_THRESHOLD)%)..."
	@if [ "$$(grep -vc '^mode:' coverage.out || true)" = "0" ]; then \
		echo "OK: no coverable statements yet (early scaffold) — threshold gate skipped."; \
	else \
		total=$$(go tool cover -func=coverage.out | awk '/^total:/ {print $$3}' | tr -d '%'); \
		if [ "$$(echo "$$total < $(COVERAGE_THRESHOLD)" | bc -l)" = "1" ]; then \
			echo "FAIL: Coverage $$total% is below $(COVERAGE_THRESHOLD)% threshold"; \
			exit 1; \
		else \
			echo "OK: Coverage $$total% meets $(COVERAGE_THRESHOLD)% threshold"; \
		fi; \
	fi
	@$(MAKE) --no-print-directory cover-domain

# design §2.2: internal/domain at 100% of statements. Skips cleanly until the
# package exists (Phase 1).
cover-domain:
	@if [ -z "$$(go list ./internal/domain/... 2>/dev/null)" ]; then \
		echo "internal/domain not present yet — skipping domain gate."; exit 0; \
	fi; \
	dpkgs=$$(go list ./internal/domain/... | tr '\n' ',' | sed 's/,$$//'); \
	go test ./internal/domain/... -count=1 -coverpkg=$$dpkgs \
		-coverprofile=coverage.domain.out -covermode=atomic >/dev/null; \
	if [ "$$(grep -vc '^mode:' coverage.domain.out || true)" = "0" ]; then \
		echo "OK: internal/domain has no statements yet."; exit 0; \
	fi; \
	dtotal=$$(go tool cover -func=coverage.domain.out | awk '/^total:/ {print $$3}' | tr -d '%'); \
	if [ "$$(echo "$$dtotal < $(DOMAIN_COVERAGE_THRESHOLD)" | bc -l)" = "1" ]; then \
		echo "FAIL: internal/domain coverage $$dtotal% is below $(DOMAIN_COVERAGE_THRESHOLD)%"; exit 1; \
	fi; \
	echo "OK: internal/domain coverage $$dtotal% meets $(DOMAIN_COVERAGE_THRESHOLD)%"

test-race:
	@echo "Running tests with race detector..."
	@go test ./... -count=1 -race

# ─── Quality ────────────────────────────────────────────────────────

# Auto-install the pinned golangci-lint into $(GOBIN) on first run. Make's
# file-target rule re-uses the binary on subsequent runs; bump
# GOLANGCI_LINT_VERSION above to refresh.
$(GOLANGCI_LINT):
	@echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION) into $(GOBIN)..."
	@GOBIN=$(abspath $(GOBIN)) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

lint: $(GOLANGCI_LINT)
	@echo "Running linter ($(GOLANGCI_LINT_VERSION))..."
	@$(GOLANGCI_LINT) run ./...

vet:
	@echo "Running go vet..."
	@go vet ./...

fmt:
	@echo "Checking formatting..."
	@files=$$(git ls-files '*.go' 2>/dev/null); \
	if [ -z "$$files" ]; then echo "no tracked Go files found"; exit 0; fi; \
	bad=$$(echo "$$files" | xargs gofmt -l); \
	if [ -n "$$bad" ]; then echo "unformatted files:"; echo "$$bad"; exit 1; fi

check: fmt vet lint test-cover
	@echo "All checks passed."

# ─── Tidy / Clean ───────────────────────────────────────────────────

tidy:
	@go mod tidy

clean:
	@rm -rf $(GOBIN) coverage.out coverage.domain.out *.db
	@echo "Cleaned."
