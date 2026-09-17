.PHONY: build dist sbom hooks test fmt vet lint lint-announce-test lint-action-pins lint-action-pins-test lint-verdict-guard lint-prose lint-prose-test cover cover-gate memcheck mutation-crypto mutation-format tidy clean schema-validate schema-validate-selftest

# VERSION is injected into main.version. A tagged build stamps the tag; otherwise
# the short commit (with -dirty), falling back to "dev" outside a git checkout.
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

# hooks points git at the tracked hooks/ directory (commit-msg and pre-commit) instead of
# the untracked, per-checkout .git/hooks/. Run once after cloning. Setting core.hooksPath
# makes git stop reading .git/hooks/ entirely, so run this instead of adding hooks there.
hooks:
	git config core.hooksPath hooks

# -shuffle=on randomises test execution order so a test can never silently depend on
# another running first; the seed is printed on failure for reproduction.
test:
	go test -race -shuffle=on ./...

# fuzz-selftest drives scripts/fuzz-bounded.sh's classifier and retry policy over canned logs with a
# stub runner: no Go toolchain, no fuzzing budget, about a second. That script decides whether a red
# fuzz job is a crasher or the Go coordinator racing its own -fuzztime expiry, so a classifier that
# has stopped classifying would either excuse every failure or fail every clean run, and both read
# like an ordinary result. This is the half you can run locally before pushing; CI runs it in the Fuzz job
# before the fuzzing itself.
fuzz-selftest:
	./scripts/fuzz-bounded.sh --self-test

fmt:
	gofmt -s -w .

vet:
	go vet ./...

# lint runs golangci-lint through scripts/lint-announce.sh, which prints what the linter excluded and how
# many Go files it walked. A configured exclusion, a //nolint comment and a narrowed target all name
# themselves in the output, so an exclusion is read on every run rather than once in a diff. The script
# resolves the linter from GOLANGCI_LINT_CMD, then GOLANGCI_LINT_VERSION (the pinned `go run` invocation
# CI uses), then the binary on PATH, and it prints which one it resolved to.
lint: lint-announce-test
	./scripts/lint-announce.sh

# lint-announce-test drives the announcement end to end with a stub linter over recorded verbose output,
# so it needs no golangci-lint, no network and about a second. It is a prerequisite of `lint` because an
# announcement that has stopped announcing reads exactly like a clean run.
lint-announce-test:
	./scripts/lint-announce.sh --self-test

# lint-action-pins-test runs the pin gate's own attack and vacuity cases offline: no token, no network,
# nothing outside node: builtins, so it costs nothing and runs anywhere. This is the half you can run
# locally before pushing.
lint-action-pins-test:
	node scripts/action-pin-comment-gate.mjs --self-test

# lint-action-pins is the graded half. Every `uses:` in .github is a 40-hex sha with a comment naming the
# release, and the comment is the only part a human reads, so a comment that disagrees with its sha is
# worse than no comment. This resolves each sha against the live GitHub ref graph and fails when the
# comment names a release the sha is not. It is not in `make lint`, and that is deliberate: it needs
# GITHUB_TOKEN and refuses with exit 2 rather than passing without one, so a mandatory chain carrying it
# would stop every contributor who has not exported a token, and its answer is a function of a third-party feed
# rather than of this commit. CI runs it in the Lint job with the workflow token.
#
# The signing step here is why it exists: sigstore/cosign-installer was pinned to a sha commented v3.7.0
# that is really v3.8.1, and the repair that reads as tidiest, moving the sha down to the tag the comment
# named, would have downgraded the release signer.
lint-action-pins: lint-action-pins-test
	node scripts/action-pin-comment-gate.mjs

# lint-verdict-guard requires every script entry point this repository runs to be enrolled in a
# completion guard, so a gate cannot reach exit 0 without reaching its own verdict. It derives the set
# from the Makefile and the workflows rather than from a list, and it needs no Go toolchain, no token and
# no network, so it runs anywhere and costs nothing. It grades ITSELF along with everything else.
#
# The Go gates are deliberately outside its scope: `go test`, `go vet`, `gofmt` and golangci-lint report
# their own verdicts, so there is no point at which this repository's code could declare one.
lint-verdict-guard:
	node scripts/verdict-guard-gate.mjs

# lint-prose grades house style, which binds this workspace and was graded here by nothing. This
# repository was recorded as having ZERO em dashes; that reading came from a .ts/.js/.md corpus, which
# matches 114 of the 1,066 tracked files and none of the 216 .go files that are the product. Measured over
# .go it holds 44, across 14 files, three of them not tests. All 44 are in COMMENTS, none in a string or in
# code, so nothing is customer-facing and nothing needed fixing on sight; they are pinned per file and per
# rule instead, and the baseline refuses an increase, an unbanked decrease and a dangling entry alike.
#
# Needs no Go toolchain, no token and no network, so it runs anywhere and costs nothing.
lint-prose-test:
	node scripts/writing-rules-source.mjs --self-test

lint-prose: lint-prose-test
	node scripts/writing-rules-source.mjs .

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

# mutation-crypto measures whether the suite actually catches a changed conditional or a
# flipped operator in the security-critical crypto core: does a mutant survive? Gremlins
# takes ONE package path (passing two silently fails), and it recompiles and re-tests once
# per mutant, so this is minutes, not seconds. A loaded machine inflates the timeout count
# and depresses the score, hence the generous coefficient. Configuration is .gremlins.yaml.
# Requires: go install github.com/go-gremlins/gremlins/cmd/gremlins@latest
#
# Baseline: 118 killed, 19 lived, 6 not covered; efficacy 86.13%, mutator
# coverage 95.80%. The survivors are dominated by equivalent mutants (capacity hints in
# make([]T, 0, n+m), which change no behaviour) and unreachable panic strings.
mutation-crypto:
	gremlins unleash --timeout-coefficient 20 --workers 2 ./internal/crypto

# mutation-format is the same over the format parse/verify path. It is much slower (the
# package's tests replay the whole conformance corpus per mutant), so it is a deliberate
# follow-up rather than a routine run.
mutation-format:
	gremlins unleash --timeout-coefficient 20 --workers 2 ./internal/format

# schema-validate confirms docs/format/schema.json is well-formed and that every
# structurally valid conformance-vector manifest and RUNLOG entry under
# internal/format/testdata/vectors/ matches it, while the deliberately malformed
# negative vectors are rejected exactly where SPEC.md says a reader rejects them
# (SPEC.md section 14). It uses ajv with the pinned lockfile in scripts/schema-validate.
#
# Requires Node. The `npm ci` is part of the recipe and runs EVERY time, so this target is the way to
# run the checker and there is nothing to install beforehand. This comment used to say the install was
# a one-off, which invited running `npm run validate` on its own against whatever was installed last:
# that tree had been two versions behind its own lockfile since 8 August, on the exact
# pins commit cd6a7797 moved to clear four npm advisories, and it still printed PASS. validate.mjs now
# holds ajv to the lockfile before it reads a vector, so that route names itself rather than passing.
#
# AND IT GOES THROUGH `npm run validate` RATHER THAN `node validate.mjs`, which is not a style choice.
# The npm script is `node --import ./arm-load-recorder.mjs validate.mjs`, and that flag is what arms the
# load census before validate.mjs's own static imports evaluate. Running the file directly refuses at
# exit 2 naming the flag, because a census whose record begins after the entry point loaded cannot see a
# module loaded before that, and an ES module loaded then is in neither the record nor the require cache.
schema-validate: schema-validate-selftest
	cd scripts/schema-validate && npm ci && npm run validate

# schema-validate-selftest drives validate.mjs's lockfile classifier over recorded key shapes: no install,
# no network, no vector read, about a second. It is a prerequisite of `schema-validate` and it needs no
# node_modules, so it is also the half you can run locally before pushing.
#
# It exists because the shape it is mostly about cannot be exercised by this repository's own lockfile.
# lockfileVersion 2 and 3 emit a versioned key per WORKSPACE MEMBER, keyed by its path rather than by an
# install location, and there is no workspace here and should not be one. Until such a key was
# compared as though it were a package name and reported NOT INSTALLED at exit 1 with the remedy `npm ci`,
# which cannot fix it: measured against a workspace npm itself created, `npm ci` exits 0, installs
# everything the lock asks for and leaves the finding byte-identical. The same offset test also let a
# genuinely nested key escape the refusal arm when its workspace prefix was shorter than `node_modules/`.
# Both are fixtures in the self-test now, alongside the superseded rules as known-positive controls.
#
# AND THE SHAPE THE FIXTURES COULD NOT SEE, because it happened before the classifier ran. Until
# evening classifyLockPackages dropped any entry whose `version` was not a string with a
# guard clause upstream of every bucket, so an entry it could not read reached no test at all and no
# count and no printed line mentioned it. Deleting ajv's version, writing it as a number or as null,
# writing the whole entry as null, or replacing the entry with `{ resolved, link: true }`, which is a
# shape npm itself writes, each left the one pin this target exists to hold uncompared and each exited
# 0. Such an entry is now a refusal at exit 2 naming the key and the reason, npm's link record for a
# workspace member is set aside rather than refused, and the run refuses unless ajv itself was compared,
# by name, so comparing the other four cannot stand in for it.
schema-validate-selftest:
	node scripts/schema-validate/validate.mjs --self-test

tidy:
	go mod tidy

clean:
	rm -rf dist build coverage.out
