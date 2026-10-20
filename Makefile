VERSION ?=
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
LDFLAGS = -s -w -X github.com/vincentsch/conformline/internal/version.Version=$(VERSION) -X github.com/vincentsch/conformline/internal/version.Commit=$(COMMIT)
PLATFORMS = linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: build build-all test race lint conformance docs docs-check clean
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/conformline$(shell go env GOEXE) ./cmd/conformline

build-all:
	@mkdir -p dist
	@set -eu; for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		output=dist/conformline-$$os-$$arch; \
		if [ "$$os" = windows ]; then output=$$output.exe; fi; \
		echo "Building $$output"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o "$$output" ./cmd/conformline; \
	done
	@cd dist && if command -v sha256sum >/dev/null 2>&1; then \
		sha256sum conformline-linux-* conformline-darwin-* conformline-windows-*.exe > checksums.txt; \
	else shasum -a 256 conformline-linux-* conformline-darwin-* conformline-windows-*.exe > checksums.txt; fi

test:
	go test ./...
race:
	go test -race ./...
lint:
	@test -z "$$(gofmt -l cmd internal)" || { gofmt -l cmd internal; exit 1; }
	go vet ./...
conformance:
	bash scripts/conformance.sh
docs:
	go run ./cmd/generate-command-docs
docs-check:
	go run ./cmd/generate-command-docs --check
clean:
	rm -f bin/conformline bin/conformline.exe dist/conformline-linux-amd64 dist/conformline-linux-arm64 dist/conformline-darwin-amd64 dist/conformline-darwin-arm64 dist/conformline-windows-amd64.exe dist/conformline-windows-arm64.exe dist/checksums.txt
