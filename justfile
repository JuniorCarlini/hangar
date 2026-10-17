set shell := ["bash", "-euo", "pipefail", "-c"]

version := `git describe --tags --always --dirty 2>/dev/null || echo dev`

# List the recipes.
default:
    @just --list

# Generate query code (sqlc), page code (templ) and the stylesheet (Tailwind).
generate:
    sqlc generate
    go tool templ generate
    just css

# Compile the stylesheet (Tailwind standalone CLI, pinned in tools/tailwind.sh).
css:
    ./tools/tailwind.sh -i internal/web/tailwind/input.css -o internal/web/assets/app.css --minify

# Format the code.
fmt:
    golangci-lint fmt

# Full lint (includes gosec).
lint:
    golangci-lint run

# Tests with the race detector.
test:
    go test -race ./...

# Integration tests against the real Docker (backups also start a
# throwaway MinIO and Postgres, named e2e-bk-*; the chaos tests kill a
# throwaway hangard mid-deploy, projects e2e-cx-*; all removed at the end).
test-integration:
    go test -race -tags integration -count=1 -timeout 30m ./internal/docker/ ./internal/alerts/ ./internal/projects/ ./internal/backup/... ./internal/chaos/

# The monitor against the real OSV.dev and Docker Hub (network; `check` uses fakes).
test-online:
    go test -tags integration -count=1 -run 'TestReal' ./internal/deps/

# End-to-end tests in a real browser (Playwright) against a throwaway panel
# (temporary data dir, free port). Kept out of `check` because it is slow;
# without Docker the container tests skip themselves.
e2e *args:
    cd e2e && npm ci --no-audit --no-fund
    cd e2e && npx playwright install chromium
    cd e2e && npx playwright test {{args}}

# Look for known vulnerabilities in dependencies and Go.
vuln:
    go tool govulncheck ./...

# Everything CI runs.
check: lint test vuln
    sqlc diff
    before=$(find internal -name '*_templ.go' -exec shasum {} + | sort); \
    go tool templ generate >/dev/null; \
    after=$(find internal -name '*_templ.go' -exec shasum {} + | sort); \
    [[ "$before" == "$after" ]] || { echo "run 'just generate': generated pages are stale"; exit 1; }
    before=$(shasum internal/web/assets/app.css); \
    just css >/dev/null 2>&1; \
    after=$(shasum internal/web/assets/app.css); \
    [[ "$before" == "$after" ]] || { echo "run 'just css': app.css is stale"; exit 1; }

# Build hangard for this machine.
build:
    go build -trimpath -ldflags "-s -w -X main.version={{version}}" -o bin/hangard ./cmd/hangard

# Build hangar-cofre, the backup tool for your computer (docs/09).
build-cofre:
    go build -trimpath -ldflags "-s -w -X main.version={{version}}" -o bin/hangar-cofre ./cmd/hangar-cofre

# hangar-cofre for macOS, Linux and Windows.
build-cofre-all:
    for target in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64; do \
      os="${target%/*}"; arch="${target#*/}"; ext=""; [[ "$os" == windows ]] && ext=".exe"; \
      GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version={{version}}" -o "bin/hangar-cofre-$os-$arch$ext" ./cmd/hangar-cofre; \
    done

# Build for the servers (Linux amd64 and arm64).
build-linux:
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version={{version}}" -o bin/hangard-linux-amd64 ./cmd/hangard
    GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version={{version}}" -o bin/hangard-linux-arm64 ./cmd/hangard

# Run the panel locally with the development config.
run: build
    ./bin/hangard serve -config hangar.dev.toml

# The public key goes into CatalogPublicKeyHex (internal/templates/remote.go),
# the private one becomes the HANGAR_CATALOG_KEY secret of hangar-templates.
# Print a new key pair for the community template catalog (docs/08).
catalog-key:
    go run ./cmd/hangard template keygen

# Check template folders with the panel's own rules (default: the embedded catalog).
template-check *dirs="internal/templates/catalog":
    go run ./cmd/hangard template check {{dirs}}

# Verify the local audit chain.
audit-verify: build
    ./bin/hangard audit verify -config hangar.dev.toml
