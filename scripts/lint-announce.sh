#!/usr/bin/env bash
# lint-announce.sh: run golangci-lint and ANNOUNCE, into the log a reviewer already reads, what the
# linter excluded and how much it walked.
#
# WHY THIS EXISTS, and why it announces rather than forbids. `linters.exclusions.paths: [".*"]` in
# .golangci.yml takes a fixture from two errcheck findings to "0 issues." and exit 0, reproduced red to
# green. The tidy answer is a gate that forbids a broad exclusion, and it was rejected: a
# rule strict enough to catch `.*` also forbids a legitimately narrow exclusion, and the repository has
# a real one already (misspell's ignore-rules for the product name "artifact"). The other tidy answer,
# leaving it to review because the change is a tracked-file edit, was rejected too. A reviewer sees a
# diff once; a log line is seen on every run, and this campaign has repeatedly found exemptions that
# read plausibly in a diff while being wrong, because the sentence stayed still while the condition it
# described moved. Announcement costs nothing and forbids nothing: an exclusion that is legitimate loses
# nothing by being named on every run.
#
# WHAT MEASUREMENT CHANGED ABOUT THE BRIEF. golangci-lint's own verbose output already carries the
# accounting, and it is wider than the configuration. On this repository at head, with no exclusions
# block in .golangci.yml at all, `run -v` prints:
#
#   [runner] Issues before processing: 1, after processing: 0
#   [runner] Processors filtering stat (in/out): ... nolint_filter: 1/0, exclusion_paths: 1/1, ...
#
# So one real issue is suppressed today, through a //nolint comment in a test file rather than through
# the configuration, and CI never ran with -v so nothing in the log said so. Announcing only the
# configuration would have missed it. This announces EVERY processing stage where the issue count going
# in differs from the count coming out, which covers configured path exclusions, exclusion rules,
# //nolint comments and generated-file filtering through one channel, in the linter's own numbers.
#
# THREE THINGS ARE ANNOUNCED:
#   1. What the linter walked: the Go files in the packages it was given, with a floor, plus any file
#      the toolchain excluded by build constraint. A build tag over the test tree, which is how this
#      repository's `go test` was taken to zero tests, moves those files out of the linted set, and the
#      count is where that shows.
#   2. What the configuration is shaped to remove: every key in .golangci.yml whose NAME matches the
#      exclusion vocabulary, with its values and line numbers. This is a name scan over the config, and
#      it is deliberately broader than `exclusions`: `disable` under linters removes findings just as
#      surely. Comments are stripped first, so a config comment discussing an exclusion is not counted
#      as one.
#   3. What was actually removed: the linter's own per-processor in/out counts.
#
# WHAT MAKES IT FAIL, which is a short list on purpose. The linter's exit status, a walked-file count
# under the floor, and the accounting line being absent from the verbose output. The last of those can
# only really happen on a golangci-lint version bump, and the version is pinned in ci.yml, so the
# failure fires exactly where the re-fitting work belongs. An announcement that silently stops
# announcing is the defect this script is about.
#
# NOTHING HERE FORBIDS AN EXCLUSION. A suppressed issue is announced and is not a failure.
#
# Run: ./scripts/lint-announce.sh            (or `make lint`)
#      ./scripts/lint-announce.sh --self-test
set -euo pipefail

# Sourcing this ARMS the completion guard: every route out of this script from here on must declare a
# verdict or the guard forces a non-zero exit.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/verdict-guard.sh"

# --self-test drives the whole script end to end with a STUB linter, so the announcement is graded
# without paying for a lint run. The stub prints a recorded verbose log and exits with a chosen status,
# which is exactly the interface the real linter presents to this script. Every assertion is paired with
# a control, because an assertion that passes on both the affected and the unaffected input is not
# measuring anything.
if [[ "${1:-}" == "--self-test" ]]; then
  bed="$(mktemp -d)"
  # NOT `trap ... EXIT`: a second EXIT trap replaces the guard's and disarms it silently, which is why
  # the verdict-guard gate treats one as a finding. The guard runs this function before it reports.
  verdict_guard_cleanup() { rm -rf "$bed"; }
  fails=0
  checked=0
  check() { # check <description> <haystack> <needle> <want-present:0|1>
    local desc="$1" hay="$2" needle="$3" want="$4" got=0
    checked=$((checked + 1))
    [[ "$hay" == *"$needle"* ]] && got=1
    if [[ "$got" != "$want" ]]; then
      echo "lint-announce --self-test FAIL: $desc (wanted present=$want, got $got) for: $needle" >&2
      fails=$((fails + 1))
    fi
  }

  cat > "$bed/stub.sh" <<'STUB'
#!/usr/bin/env bash
cat "$STUB_LOG"
exit "${STUB_EXIT:-0}"
STUB
  chmod +x "$bed/stub.sh"

  # A run where nothing was removed: every stage passed on what it was given.
  cat > "$bed/clean.log" <<'LOG'
level=info msg="[config_reader] Used config file .golangci.yml"
level=info msg="[lintersdb] Active 12 linters: [errcheck gocritic gofmt goimports govet ineffassign misspell prealloc revive staticcheck unconvert unused]"
level=info msg="[runner] Processors filtering stat (in/out): invalid_issue: 2/2, exclusion_paths: 2/2, nolint_filter: 2/2, cgo: 2/2"
2 issues.
LOG
  # The repo-wide exclusion, transcribed from a real run of golangci-lint v2.12.2 over a fixture whose
  # .golangci.yml carried `linters.exclusions.paths: [".*"]`: two errcheck findings in, none out, and
  # the linter exits 0.
  cat > "$bed/excluded.log" <<'LOG'
level=info msg="[config_reader] Used config file .golangci.yml"
level=info msg="[lintersdb] Active 1 linters: [errcheck]"
level=info msg="[runner] Issues before processing: 2, after processing: 0"
level=info msg="[runner] Processors filtering stat (in/out): invalid_issue: 2/2, exclusion_paths: 2/0, path_absoluter: 2/2, cgo: 2/2"
0 issues.
LOG
  # The suppression this repository really carries at head, and it is not a configured one.
  cat > "$bed/nolint.log" <<'LOG'
level=info msg="[config_reader] Used config file .golangci.yml"
level=info msg="[lintersdb] Active 12 linters: [errcheck gocritic gofmt goimports govet ineffassign misspell prealloc revive staticcheck unconvert unused]"
level=info msg="[runner] Issues before processing: 1, after processing: 0"
level=info msg="[runner] Processors filtering stat (in/out): nolint_filter: 1/0, cgo: 1/1, exclusion_paths: 1/1, exclusion_rules: 1/1"
0 issues.
LOG
  # A verbose log with no accounting line at all, which is what a version bump that renames the line
  # would produce.
  cat > "$bed/noaccounting.log" <<'LOG'
level=info msg="[config_reader] Used config file .golangci.yml"
level=info msg="[lintersdb] Active 12 linters: [errcheck]"
0 issues.
LOG
  # Two configurations: one whose only mention of an exclusion is in a COMMENT, one carrying a real key.
  cat > "$bed/comment-only.yml" <<'YML'
version: "2"
# This comment discusses an exclusion and an ignore-rules block at length, and it excludes nothing.
linters:
  enable:
    - errcheck
YML
  cat > "$bed/has-exclusions.yml" <<'YML'
version: "2"
linters:
  enable:
    - errcheck
  exclusions:
    paths:
      - ".*"
YML

  run_stub() { # run_stub <log> <exit> [extra env assignments...]
    local log="$1" code="$2"
    shift 2
    env STUB_LOG="$log" STUB_EXIT="$code" GOLANGCI_LINT_CMD="$bed/stub.sh" "$@" "$0" 2>&1
  }

  clean_out="$(run_stub "$bed/clean.log" 0 LINT_ANNOUNCE_CONFIG="$bed/comment-only.yml")"; clean_code=$?
  excl_out="$(run_stub "$bed/excluded.log" 0 LINT_ANNOUNCE_CONFIG="$bed/has-exclusions.yml")" || true
  run_stub "$bed/excluded.log" 0 LINT_ANNOUNCE_CONFIG="$bed/has-exclusions.yml" >/dev/null 2>&1 && excl_code=0 || excl_code=$?
  nolint_out="$(run_stub "$bed/nolint.log" 0 LINT_ANNOUNCE_CONFIG="$bed/comment-only.yml")"; nolint_code=$?

  # THE ASSERTION THIS SCRIPT EXISTS FOR: a repo-wide exclusion is visible in the log rather than only
  # in the config, and the run it appears on is a PASSING run.
  check "a repo-wide path exclusion is announced" "$excl_out" "exclusion_paths suppressed 2 issue(s)" 1
  check "the announcement names the exclusion as repo-wide in the config" "$excl_out" '- ".*"' 1
  check "a repo-wide path exclusion does not fail the run" "$excl_code" "0" 1
  check "the announcement says how many issues the linter found before filtering" "$excl_out" "found 2 issue(s) before filtering, reported 0 after" 1
  # The control. The same script over a log where no stage removed anything must NOT print a suppression.
  check "a run with nothing suppressed says so" "$clean_out" "no stage removed an issue" 1
  check "a run with nothing suppressed announces no suppression" "$clean_out" "suppressed" 0
  check "a run with nothing suppressed exits 0" "$clean_code" "0" 1
  # The channel the configuration scan cannot see.
  check "a //nolint suppression is announced" "$nolint_out" "nolint_filter suppressed 1 issue(s)" 1
  check "a //nolint suppression does not fail the run" "$nolint_code" "0" 1
  check "a //nolint suppression is announced even with no exclusion key in the config" "$nolint_out" "no key in" 1

  # The configuration scan: a real key is named with its line, a comment mentioning one is not.
  check "an exclusions key in the config is named" "$excl_out" "exclusions:" 1
  check "a config comment mentioning an exclusion is not counted as one" "$clean_out" "no key in" 1

  # The walked-file floor, and its control.
  floor_out="$(run_stub "$bed/clean.log" 0 LINT_ANNOUNCE_CONFIG="$bed/comment-only.yml" LINT_FILE_FLOOR=1000000)" || true
  run_stub "$bed/clean.log" 0 LINT_ANNOUNCE_CONFIG="$bed/comment-only.yml" LINT_FILE_FLOOR=1000000 >/dev/null 2>&1 && floor_code=0 || floor_code=$?
  check "a walked-file count under the floor fails" "$floor_code" "1" 1
  check "a walked-file count under the floor says so" "$floor_out" "under the floor of 1000000" 1
  check "an ordinary run carries no floor finding" "$clean_out" "under the floor of" 0
  check "an ordinary run announces what it walked" "$clean_out" "Go file(s) across" 1

  # The accounting going missing must be loud, not silent.
  missing_out="$(run_stub "$bed/noaccounting.log" 0 LINT_ANNOUNCE_CONFIG="$bed/comment-only.yml")" || true
  run_stub "$bed/noaccounting.log" 0 LINT_ANNOUNCE_CONFIG="$bed/comment-only.yml" >/dev/null 2>&1 && missing_code=0 || missing_code=$?
  check "an absent accounting line fails" "$missing_code" "1" 1
  check "an absent accounting line says the announcement could not be made" "$missing_out" "printed no filtering accounting" 1
  check "an ordinary run does not claim the accounting is absent" "$clean_out" "printed no filtering accounting" 0

  # The linter's own verdict still decides the run, and it is not softened by anything above.
  fail_out="$(run_stub "$bed/clean.log" 1 LINT_ANNOUNCE_CONFIG="$bed/comment-only.yml")" || true
  run_stub "$bed/clean.log" 1 LINT_ANNOUNCE_CONFIG="$bed/comment-only.yml" >/dev/null 2>&1 && fail_code=0 || fail_code=$?
  check "a linter that exits 1 fails this script" "$fail_code" "1" 1
  check "a linter that exits 1 is named in the verdict" "$fail_out" "VERDICT: FAIL" 1
  check "a linter that exits 0 reaches a passing verdict" "$clean_out" "VERDICT: PASS" 1
  # The linter's own output has to reach the log, or the announcement has replaced the thing it annotates.
  check "the linter's own output is printed" "$clean_out" "2 issues." 1

  if (( fails > 0 )); then
    echo "lint-announce --self-test: $fails of $checked assertion(s) failed" >&2
    verdict_reached "$fails" "$checked"
    exit 1
  fi
  echo "lint-announce --self-test: $checked assertions passed (a suppression is announced, a run with none says so, the floor and the missing-accounting case both fail, and the linter's own status still decides the run)"
  verdict_reached 0 "$checked"
  exit 0
fi

config="${LINT_ANNOUNCE_CONFIG:-.golangci.yml}"
# The floor is over the Go files in the packages the linter was given. It sits under the current count
# (192) so ordinary churn does not trip it, while narrowing `./...` to one package, or
# build-tagging the test tree out of the build, cannot pass as a full run. It does NOT catch a path
# exclusion: an exclusion filters issues, not files, which is why the announcement below exists.
file_floor="${LINT_FILE_FLOOR:-150}"

bed="$(mktemp -d)"
verdict_guard_cleanup() { rm -rf "$bed"; }

# The linter command. CI passes GOLANGCI_LINT_VERSION and gets the pinned `go run` invocation; an
# environment with the binary installed gets that instead. Whatever it resolves to is PRINTED in the announcement,
# so a substituted linter announces itself rather than being taken on trust.
linter=()
if [[ -n "${GOLANGCI_LINT_CMD:-}" ]]; then
  read -r -a linter <<< "$GOLANGCI_LINT_CMD"
elif [[ -n "${GOLANGCI_LINT_VERSION:-}" ]]; then
  linter=(go run "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}")
elif command -v golangci-lint >/dev/null 2>&1; then
  linter=(golangci-lint)
else
  echo "lint-announce: no golangci-lint available. Set GOLANGCI_LINT_VERSION for the pinned go run invocation, or install the binary" >&2
  # A missing linter is a skip rather than a pass: nothing was linted, so nothing could have failed.
  verdict_skipped "no golangci-lint available, so no package was linted" require
  exit 1
fi

targets=("$@")
[[ ${#targets[@]} -eq 0 ]] && targets=("./...")

# What the linter was given, counted before it runs, so a count of zero is still reported. A `go list`
# failure leaves the counts at zero and the floor below is what says so: `set -euo pipefail` does not
# reach into a process substitution, and a loop that reads nothing otherwise passes having examined
# nothing at all.
walked=0
packages=0
constrained_out=0
if go list -f '{{len .GoFiles}} {{len .CgoFiles}} {{len .TestGoFiles}} {{len .XTestGoFiles}} {{len .IgnoredGoFiles}}' "${targets[@]}" > "$bed/files.txt" 2> "$bed/golist.err"; then
  while read -r n_go n_cgo n_test n_xtest n_ignored; do
    packages=$((packages + 1))
    walked=$((walked + n_go + n_cgo + n_test + n_xtest))
    constrained_out=$((constrained_out + n_ignored))
  done < "$bed/files.txt"
else
  echo "lint-announce: go list over ${targets[*]} failed, so the walked-file count below is zero rather than unknown" >&2
  cat "$bed/golist.err" >&2
fi

lint_status=0
"${linter[@]}" run -v "${targets[@]}" > "$bed/lint.log" 2>&1 || lint_status=$?
# The linter's own output first and in full, because the announcement annotates it rather than replacing
# it, and the verdict belongs last.
cat "$bed/lint.log"

active="$(sed -n 's/.*\[lintersdb\] \(Active [0-9]* linters: \[[^]]*\]\).*/\1/p' "$bed/lint.log" | tail -1)"
config_used="$(sed -n 's/.*\[config_reader\] Used config file \(.*\)"$/\1/p' "$bed/lint.log" | tail -1)"
before_after="$(sed -n 's/.*\[runner\] Issues before processing: \([0-9]*\), after processing: \([0-9]*\).*/found \1 issue(s) before filtering, reported \2 after/p' "$bed/lint.log" | tail -1)"
stat_line="$(sed -n 's/.*Processors filtering stat (in\/out): \(.*\)"$/\1/p' "$bed/lint.log" | tail -1)"

findings=0

echo
echo "golangci-lint announcement: what it excluded, and how much it walked"
echo "  invoked as: ${linter[*]} run -v ${targets[*]}"
echo "  configuration the linter reports reading: ${config_used:-none}"
echo "  ${active:-active linter set not reported}"
echo "  walked: $walked Go file(s) across $packages package(s), floor $file_floor"
if [[ "$constrained_out" -gt 0 ]]; then
  echo "  excluded by build constraint before the linter saw them: $constrained_out file(s) in those packages"
else
  echo "  excluded by build constraint before the linter saw them: none"
fi

# The configuration scan. Comments are stripped first: a scanner that reads comments as code is its own
# bug class and has produced a false negative in a sibling repository's gate. The vocabulary is wider
# than `exclusions` because `disable` under linters removes findings just as surely.
config_hits="$(
  if [[ -f "$config" ]]; then
    awk '
      {
        line = $0
        sub(/^[ \t]*#.*$/, "", line)
        sub(/[ \t]+#.*$/, "", line)
        if (line ~ /^[ \t]*$/) next
        match(line, /^[ \t]*/)
        indent = RLENGTH
        if (capturing && indent > cap_indent) { printf "    %d: %s\n", NR, line; next }
        capturing = 0
        key = line
        sub(/^[ \t]*/, "", key)
        if (key ~ /^-/) next
        sub(/:.*$/, "", key)
        if (tolower(key) ~ /(exclusion|exclude|ignore|skip|disable|nolint)/) {
          printf "    %d: %s\n", NR, line
          capturing = 1
          cap_indent = indent
        }
      }
    ' "$config"
  fi
)"
if [[ -n "$config_hits" ]]; then
  echo "  keys in $config whose name is exclusion-shaped (exclusion, exclude, ignore, skip, disable, nolint), with their values:"
  printf '%s\n' "$config_hits"
else
  echo "  no key in ${config} is exclusion-shaped, so nothing in the configuration is named to remove a finding"
fi

echo "  the linter's own filtering accounting:"
if [[ -z "$stat_line" ]]; then
  echo "    this linter printed no filtering accounting, so what it excluded CANNOT be announced from this run." >&2
  echo "    The line looked for is \"Processors filtering stat (in/out)\" in the -v output. golangci-lint is pinned by version in ci.yml, so this is a version bump that renamed it, and the fix is to re-fit this script to the new wording rather than to drop the announcement." >&2
  findings=$((findings + 1))
else
  [[ -n "$before_after" ]] && echo "    $before_after"
  suppressed_stages=0
  stages=0
  # Split on the comma once, with globbing off so a stage name could never be expanded against the
  # working directory, and put IFS back immediately. The stages arrive in Go map order, which differs
  # run to run, so nothing below may depend on their position.
  old_ifs="$IFS"
  IFS=','
  set -f
  parts=($stat_line)
  set +f
  IFS="$old_ifs"
  for part in "${parts[@]}"; do
    stage="$(printf '%s' "${part%%:*}" | tr -d ' ')"
    counts="$(printf '%s' "${part#*:}" | tr -d ' ')"
    in_count="${counts%%/*}"
    out_count="${counts##*/}"
    [[ "$in_count" =~ ^[0-9]+$ && "$out_count" =~ ^[0-9]+$ ]] || continue
    stages=$((stages + 1))
    if [[ "$in_count" -gt "$out_count" ]]; then
      echo "    $stage suppressed $((in_count - out_count)) issue(s) ($in_count in, $out_count out)"
      suppressed_stages=$((suppressed_stages + 1))
    fi
  done
  # NEITHER LINE MAY READ AS A VERDICT. golangci-lint can exit 1 on real findings while a stage also
  # suppressed something, so both of these can print above a FAILED verdict, and a reader scanning a red
  # log must not meet a word that reads like a pass. The verdict is the VERDICT line at the end.
  if [[ "$suppressed_stages" -eq 0 ]]; then
    echo "    no stage removed an issue: all $stages accounted stage(s) reported the same count in and out"
  else
    echo "    an issue removed here is named rather than forbidden, and naming it changes no verdict either way."
  fi
fi

if [[ "$walked" -lt "$file_floor" ]]; then
  echo "::error::lint-announce: golangci-lint was given $walked Go file(s), under the floor of $file_floor, so this run has not looked at what it claims to cover" >&2
  findings=$((findings + 1))
fi

if [[ "$lint_status" -ne 0 ]]; then
  echo "lint-announce: golangci-lint exited $lint_status, so its findings above stand" >&2
  findings=$((findings + 1))
fi

# `walked` is the population every statement above was made over, and the floor already refuses a run
# that walked too few. The guard refuses a zero independently.
verdict_reached "$findings" "$walked"
[[ "$findings" -eq 0 ]] || exit 1
