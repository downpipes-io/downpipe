.PHONY: build dist sbom test fuzz-selftest fmt vet lint cover cover-gate memcheck tidy clean schema-validate

# VERSION is injected into main.version. A tagged build stamps the tag; otherwise the
# short commit (with -dirty), falling back to "dev" outside a git checkout.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

build:
	go build ./...

# dist builds a single version-stamped, trimmed binary into ./build (the release
# pipeline uses goreleaser; this is the local equivalent for a quick stamped build).
dist:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o build/downpipe ./cmd/downpipe

# sbom writes a CycloneDX SBOM (sbom.cdx.json) via scripts/generate-sbom.sh.
sbom:
	./scripts/generate-sbom.sh

# -shuffle=on randomises test execution order so a test can never silently depend on
# another running first; the seed is printed on failure for reproduction.
test:
	go test -race -shuffle=on ./...

# fuzz-selftest drives scripts/fuzz-bounded.sh's classifier and retry policy over canned
# logs with a stub runner: no Go toolchain, no fuzzing budget, about a second. That
# script tells a crasher apart from the Go coordinator racing its own -fuzztime expiry.
# Run this locally before pushing; CI runs it in the Fuzz job before the fuzzing itself.
fuzz-selftest:
	./scripts/fuzz-bounded.sh --self-test

fmt:
	gofmt -s -w .

vet:
	go vet ./...

lint:
	golangci-lint run ./...

cover:
	go test -race -shuffle=on -coverpkg=./... -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

# cover-gate is the gate CI enforces: per-package statement floors (internal/crypto 90%,
# every other package 85%) computed from the profile's statement blocks. -coverpkg so a
# package's coverage counts the tests that actually exercise it, wherever they live.
cover-gate:
	go test -race -shuffle=on -coverpkg=./... -coverprofile=coverage.out ./...
	./scripts/coverage-gate.sh coverage.out

# memcheck runs the memory tripwires for the streaming restore path: peak heap must not
# scale with the largest record in the archive. Opt-in (the tests are skipped otherwise)
# because they build and restore real archives.
memcheck:
	DOWNPIPE_MEMCHECK=1 go test -run TestMemcheck -v ./internal/restore/

# schema-validate confirms docs/format/schema.json is well-formed and that every
# structurally valid conformance-vector manifest and RUNLOG entry under
# internal/format/testdata/vectors/ matches it, while the deliberately malformed
# negative vectors are rejected exactly where SPEC.md says a reader rejects them
# (SPEC.md section 14). It uses ajv with the pinned lockfile in scripts/schema-validate.
schema-validate:
	cd scripts/schema-validate && npm ci && npm run validate

tidy:
	go mod tidy

clean:
	rm -rf dist build coverage.out
