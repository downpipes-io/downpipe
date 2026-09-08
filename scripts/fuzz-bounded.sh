#!/usr/bin/env bash
# fuzz-bounded.sh: runs the bounded native-fuzz pass and tells a clean budget expiry apart
# from a finding, so the fuzz job goes red for a crasher and only for a crasher.
#
# WHY THIS EXISTS. A budget-expiry race can go red on `Fuzz (./internal/restore)`
# with no crasher recorded. The whole failure
# was two lines:
#
#     --- FAIL: FuzzDirTargetKey (40.64s)
#         context deadline exceeded
#
# No failing input, no panic, no reproducer written under testdata/fuzz, nothing to re-run.
# The SAME sha had already been graded green: workflow_dispatch run 31295175449 ran the same
# target to 41.013s and passed, push run 31296351130 failed. Same tree, same job, opposite
# outcomes, and a dispatch run green is not a push run green.
#
# THE SIGNATURE IS NOT SPECIFIC TO A TARGET OR A PACKAGE, which is what rules out a defect in
# the code under test. Three occurrences, two packages, three targets, one failure text:
#
#     run 30900154660  FuzzRunlogKeyless  (40.07s)  context deadline exceeded
#     run 30953694916  FuzzManifest       (41.03s)  context deadline exceeded
#     run 31296351130  FuzzDirTargetKey   (40.64s)  context deadline exceeded
#
# Reproduced locally at 1 in 40 with `-fuzztime 3s -parallel 2` on an unmodified tree, with
# `git status --porcelain` empty afterwards, so nothing was written to the corpus there either.
#
# THE MECHANISM, read out of the Go source rather than guessed. internal/fuzz/fuzz.go's
# CoordinateFuzzing wraps its context with WithTimeout(fuzztime) and derives
# `fuzzCtx := WithCancel(ctx)` from it. Budget expiry is the NORMAL termination path: the main
# select takes `case <-doneC: stop(ctx.Err())`, and stop suppresses that error only through
#
#     if err == fuzzCtx.Err() || isInterruptError(err) { err = nil }
#
# context.go's cancelCtx.cancel closes its OWN done channel BEFORE it walks
# `for child := range c.children { child.cancel(...) }`, so a goroutine woken by the parent can
# read the child's Err() while it is still nil. The comparison then fails, context.DeadlineExceeded
# is recorded as fuzzErr, and a clean stop is printed as a test failure. Every duration-budgeted
# fuzz run rolls this dice once, on a two-CPU runner, in parallel rather than by interleaving.
#
# WHAT THIS SCRIPT DOES ABOUT IT. It classifies a non-zero `go test -fuzz` rather than trusting
# the exit status alone, and it re-runs ONLY the bare-deadline signature, once:
#
#   crasher       a file appeared under the target's testdata/fuzz corpus, or the log says
#                 "Failing input written to". FAIL, immediately, never retried. This is checked
#                 FIRST and independently of the log text, so a crash that also carries the
#                 deadline message (the coordinator writes the crasher from a defer even when
#                 fuzzErr is the deadline error) is still a crash.
#   deadline-race a `--- FAIL` whose only reported detail is a bare "context deadline exceeded",
#                 with nothing added to the corpus. Re-run once. A repeat FAILS the job.
#   other         anything else: a panic, a build error, a vet failure. FAIL.
#
# THE TRADE, stated rather than hidden. A fuzz function that HANGS presents the same way: the
# coordinator's `if ctx.Err() != nil { return ctx.Err() }` in worker.go is reached before the
# hang is classified, so a hang at the budget boundary also prints a bare deadline error and
# writes nothing. This script will excuse the first such run and fail on the second. That is a
# real loss of one attempt, and it buys the far larger one: at roughly one race per hundred
# target-runs over nine targets, a false red landed on main about every twenty pushes, and a
# main that is red for reasons nobody can act on is how a real red goes unread for an hour.
# The excused run prints the fuzzer's last statistics line, because a hang shows there as
# execs that stopped advancing while a race does not.
#
# Usage:
#   scripts/fuzz-bounded.sh --self-test
#   scripts/fuzz-bounded.sh <pkg> <fuzztime> <target> [<target> ...]

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Two attempts, not three. One re-run takes the chance of a false red from about 1 in 100 to about
# 1 in 10,000 per target; a third would buy nothing measurable and would spend another whole budget
# on the run where something is genuinely wrong.
max_attempts=2

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/fuzz-bounded.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

attempts=0
failures=0

# corpus_state lists the corpus files for one target, sorted, so "a crasher was written" is a
# comparison of two listings rather than a guess from the log text. A missing directory is an
# empty listing, not an error: a target with no committed seeds has no directory until one is
# written, and that first write is exactly the case this must catch.
corpus_state() {
  local dir="$1"
  if [[ -d "$dir" ]]; then
    find "$dir" -type f | LC_ALL=C sort
  fi
}

# classify <log> <before-listing> <after-listing> -> crasher | deadline-race | other
classify() {
  local log="$1" before="$2" after="$3"
  if ! cmp -s "$before" "$after"; then
    echo crasher
    return 0
  fi
  if grep -Fq "Failing input written to" "$log"; then
    echo crasher
    return 0
  fi
  # Both halves are required. A run that says "--- FAIL" for some other reason and happens to
  # mention a deadline somewhere is not this, and a deadline line with no FAIL at all is not a
  # failure to excuse. The deadline line is anchored whole so a longer message that merely wraps
  # the deadline error (a crash reported during minimisation, say) is not read as a bare one.
  if grep -q '^--- FAIL' "$log" && grep -Eq '^[[:space:]]+context deadline exceeded[[:space:]]*$' "$log"; then
    echo deadline-race
    return 0
  fi
  echo other
}

# fuzz_invoke is the single point at which this script shells out, so --self-test can drive the
# whole retry policy with a stub and no Go toolchain, no corpus and no minutes.
fuzz_invoke() {
  local pkg="$1" target="$2" budget="$3" log="$4"
  go test "$pkg" -run '^$' -fuzz "^${target}\$" -fuzztime "$budget" >"$log" 2>&1
}

# run_target <pkg> <target> <budget> <corpus-dir> -> 0 pass, 1 fail
run_target() {
  local pkg="$1" target="$2" budget="$3" corpus="$4"
  local attempt=1 rc verdict log before after
  while [[ "$attempt" -le "$max_attempts" ]]; do
    log="$tmpdir/$target.$attempt.log"
    before="$tmpdir/$target.$attempt.before"
    after="$tmpdir/$target.$attempt.after"
    corpus_state "$corpus" >"$before"
    # The status is read from the command DIRECTLY into rc, never off the end of a pipe. The log
    # is written to a file and printed afterwards for the same reason: `go test ... | tee` reports
    # tee's status, and this repository has already been given a false answer that way.
    #
    # `|| rc=$?` rather than `set +e; ...; set -e`. `set` is process-global, not scoped to a
    # function, so re-arming errexit here overrides whatever the caller had turned off and the
    # function's own `return 1` then kills the process instead of being handled. That was not
    # hypothetical: it took the self-test's repeated-race case out before it could assert.
    rc=0
    fuzz_invoke "$pkg" "$target" "$budget" "$log" || rc=$?
    attempts=$((attempts + 1))
    cat "$log"
    if [[ "$rc" -eq 0 ]]; then
      return 0
    fi
    corpus_state "$corpus" >"$after"
    verdict="$(classify "$log" "$before" "$after")"
    case "$verdict" in
      deadline-race)
        if [[ "$attempt" -lt "$max_attempts" ]]; then
          echo "::warning title=fuzz budget expiry raced::${pkg} ${target} exited ${rc} with a bare \"context deadline exceeded\" and wrote no crasher. That is the Go coordinator racing its own -fuzztime expiry, not a finding. Re-running once; a repeat fails the job."
          echo "  last statistics line before the expiry (a hang shows here as execs that stopped advancing):"
          grep '^fuzz: elapsed' "$log" | tail -n 1 || true
          attempt=$((attempt + 1))
          continue
        fi
        echo "::error title=fuzz deadline signature repeated::${pkg} ${target} hit \"context deadline exceeded\" on ${max_attempts} consecutive attempts and wrote no crasher. Two independent races is not a race. Treat this as a hanging input or a broken toolchain, not as noise." >&2
        ;;
      crasher)
        echo "::error title=fuzz crasher::${pkg} ${target} found a crasher. The failing input is under $(printf '%s' "${corpus#"$repo_root/"}"); commit it as a seed so the short CI pass pins it from now on." >&2
        ;;
      *)
        echo "::error title=fuzz failed::${pkg} ${target} exited ${rc} for a reason that is neither a crasher nor a budget expiry. Read the log above." >&2
        ;;
    esac
    return 1
  done
  return 1
}

if [[ "${1:-}" == "--self-test" ]]; then
  # The self-test drives the classifier and the retry policy with canned logs and a stub runner:
  # no Go toolchain, no network, no fuzzing budget, about a second. It exists because a
  # classifier that has stopped classifying reads exactly like a clean run, and because the one
  # thing this script must never do is retry a crash away.
  checks=0
  fails=0
  st_dir="$tmpdir/selftest"
  mkdir -p "$st_dir"

  assert_eq() {
    local want="$1" got="$2" desc="$3"
    checks=$((checks + 1))
    if [[ "$want" != "$got" ]]; then
      echo "fuzz-bounded --self-test FAIL: $desc (wanted \"$want\", got \"$got\")" >&2
      fails=$((fails + 1))
    fi
  }

  # --- the classifier, over the real texts ---------------------------------------------------
  : >"$st_dir/empty-a"
  : >"$st_dir/empty-b"

  # The exact two lines from push run 31296351130, with the surrounding text `go test` prints.
  printf -- 'fuzz: elapsed: 41s, execs: 536575 (7233/sec), new interesting: 126 (total: 163)\n--- FAIL: FuzzDirTargetKey (40.64s)\n    context deadline exceeded\nFAIL\nexit status 1\nFAIL\tgithub.com/downpipes-io/downpipe/internal/restore\t40.643s\n' >"$st_dir/race.log"
  assert_eq "deadline-race" "$(classify "$st_dir/race.log" "$st_dir/empty-a" "$st_dir/empty-b")" \
    "the CI failure text with an unchanged corpus is the budget-expiry race"

  # A crasher that ALSO carries the deadline text. The coordinator writes the crasher from a
  # defer while fuzzErr is still the deadline error, so this ordering is reachable and it is the
  # one case where excusing the deadline line would lose a real finding.
  printf -- '--- FAIL: FuzzDirTargetKey (40.64s)\n    context deadline exceeded\n    Failing input written to testdata/fuzz/FuzzDirTargetKey/9f3a\n' >"$st_dir/crash-with-deadline.log"
  assert_eq "crasher" "$(classify "$st_dir/crash-with-deadline.log" "$st_dir/empty-a" "$st_dir/empty-b")" \
    "a crasher that also prints the deadline line is a crasher, not a race"

  # A corpus that gained a file outranks whatever the log says, because the file is the finding.
  printf 'testdata/fuzz/FuzzDirTargetKey/9f3a\n' >"$st_dir/grew"
  assert_eq "crasher" "$(classify "$st_dir/race.log" "$st_dir/empty-a" "$st_dir/grew")" \
    "a corpus that gained a file is a crasher whatever the log text says"

  printf -- '--- FAIL: FuzzDirTargetKey (0.03s)\n    panic: runtime error: index out of range [4] with length 4\n' >"$st_dir/panic.log"
  assert_eq "other" "$(classify "$st_dir/panic.log" "$st_dir/empty-a" "$st_dir/empty-b")" \
    "a panic with no corpus write is not excused as a race"

  printf 'internal/restore/target_dir.go:41:2: undefined: safeKey\nFAIL\tgithub.com/downpipes-io/downpipe/internal/restore [build failed]\n' >"$st_dir/build.log"
  assert_eq "other" "$(classify "$st_dir/build.log" "$st_dir/empty-a" "$st_dir/empty-b")" \
    "a build failure is not excused as a race"

  # The narrowness control: the deadline words alone, with no FAIL line, must not be excused.
  # Without this the classifier would excuse any failing run whose log happened to mention a
  # deadline anywhere, which is a far wider excuse than the one this script is for.
  printf 'some tool reported context deadline exceeded while fetching\nFAIL\texit status 2\n' >"$st_dir/mention.log"
  assert_eq "other" "$(classify "$st_dir/mention.log" "$st_dir/empty-a" "$st_dir/empty-b")" \
    "the deadline words without a --- FAIL line are not the race"

  # --- the two halves of the deadline test, each held down on its own -------------------------
  # The control above passes for the WRONG REASON on either half alone: its deadline words carry
  # a prefix, so they fail the anchor before the --- FAIL test is ever consulted. Measured, not
  # argued: replacing the anchored match with `grep -Fq 'context deadline exceeded'`, and
  # separately dropping the `--- FAIL` conjunct outright, each left all twelve of the assertions
  # that preceded these green. The three controls below are what make each half load-bearing.

  # HALF ONE, the anchor, against a wrapped deadline error. DRIVEN, not composed: this is the
  # output of `go test -fuzz` over a seed whose fuzz function reports context.DeadlineExceeded
  # inside its own sentence, with the module and file names changed to this repository's. It is
  # the case the anchor exists for and it is not a rare one: the seed pass runs before fuzzing
  # begins, so the failing input is one the coordinator was given rather than one it generated,
  # nothing is added to the corpus and no "Failing input written to" is printed. Both crasher
  # escapes are therefore unavailable and the verdict rests on this line alone.
  # Unanchored, a real and possibly intermittent finding is re-run once and announced to the
  # operator as "not a finding".
  printf -- 'fuzz: elapsed: 0s, gathering baseline coverage: 0/2 completed\nfailure while testing seed corpus entry: FuzzDirTargetKey/seed#1\nfuzz: elapsed: 0s, gathering baseline coverage: 1/2 completed\n--- FAIL: FuzzDirTargetKey (0.02s)\n    --- FAIL: FuzzDirTargetKey (0.00s)\n        target_dir_test.go:22: restore plan: context deadline exceeded\n    \nFAIL\nexit status 1\nFAIL\tgithub.com/downpipes-io/downpipe/internal/restore\t0.626s\n' >"$st_dir/wrapped-prefix.log"
  assert_eq "other" "$(classify "$st_dir/wrapped-prefix.log" "$st_dir/empty-a" "$st_dir/empty-b")" \
    "a seed failure that reports the deadline error inside its own sentence is a finding, not the race"

  # HALF ONE, the other end of the anchor. CONSTRUCTED rather than driven, and said so plainly:
  # every wrapping `go test` was observed to emit puts something BEFORE the deadline words, so a
  # trailing-detail line could not be produced from the toolchain here. The property the comment
  # states is that the line matches WHOLE, and only a line with trailing detail can hold the tail
  # of that down, so the control is written rather than left unasserted.
  printf -- '--- FAIL: FuzzDirTargetKey (40.64s)\n    context deadline exceeded while minimising the crash found at 40.61s\nFAIL\nexit status 1\n' >"$st_dir/wrapped-suffix.log"
  assert_eq "other" "$(classify "$st_dir/wrapped-suffix.log" "$st_dir/empty-a" "$st_dir/empty-b")" \
    "the deadline words carrying trailing detail are not the bare line"

  # HALF TWO, the --- FAIL conjunct, against a log whose deadline line IS the bare anchored shape.
  # mention.log cannot hold this half down because its line never matches the anchor. Also
  # CONSTRUCTED: within one `go test` invocation the coordinator's error is printed through the
  # test writer and so always arrives under a --- FAIL, which is exactly why the conjunct is
  # cheap insurance rather than a live filter. A log this script is handed is one invocation
  # today; the conjunct is what keeps that true if it is ever handed a wider one.
  printf -- 'ok  \tgithub.com/downpipes-io/downpipe/internal/manifest\t0.412s\n    context deadline exceeded\nFAIL\tgithub.com/downpipes-io/downpipe/internal/restore\t40.643s\n' >"$st_dir/no-fail-line.log"
  assert_eq "other" "$(classify "$st_dir/no-fail-line.log" "$st_dir/empty-a" "$st_dir/empty-b")" \
    "the bare deadline line with no --- FAIL anywhere is not the race"

  # --- the retry policy, driven end to end with a stub -----------------------------------------
  st_corpus="$st_dir/corpus"
  mkdir -p "$st_corpus"
  stub_calls=0
  stub_races=0
  stub_writes_crasher=0
  stub_panics=0
  fuzz_invoke() {
    stub_calls=$((stub_calls + 1))
    if [[ "$stub_writes_crasher" -eq 1 ]]; then
      mkdir -p "$st_corpus"
      printf 'x' >"$st_corpus/deadbeef"
      printf -- '--- FAIL: %s (40.6s)\n    context deadline exceeded\n' "$2" >"$4"
      return 1
    fi
    if [[ "$stub_panics" -eq 1 ]]; then
      printf -- '--- FAIL: %s (0.03s)\n    panic: runtime error: index out of range [4] with length 4\n' "$2" >"$4"
      return 1
    fi
    if [[ "$stub_calls" -le "$stub_races" ]]; then
      printf -- 'fuzz: elapsed: 40s, execs: 500000 (12000/sec), new interesting: 3 (total: 90)\n--- FAIL: %s (40.6s)\n    context deadline exceeded\nFAIL\nexit status 1\n' "$2" >"$4"
      return 1
    fi
    printf 'PASS\nok  \t%s\t40.1s\n' "$1" >"$4"
    return 0
  }

  # The output is captured rather than discarded. What run_target PRINTS is not decoration: the
  # ::error annotations are the whole of what a human is told about a red fuzz job, and dropping
  # any of them left every assertion here green.
  stub_calls=0
  stub_races=1
  rc=0
  run_target ./stub FuzzStub 40s "$st_corpus" >"$st_dir/out.race" 2>&1 || rc=$?
  assert_eq "0" "$rc" "one race then a clean run passes the target"
  assert_eq "2" "$stub_calls" "one race costs exactly one extra attempt"
  assert_eq "1" "$(grep -c '^::warning title=fuzz budget expiry raced' "$st_dir/out.race" || true)" \
    "the excused run says so, once, as a warning annotation"
  # Not a count: the fuzzer's own log carries a statistics line too, so a count cannot tell the
  # printed log apart from the line the retry path pulls out. This reads the line that follows the
  # label, which only the retry path writes.
  assert_eq "fuzz: elapsed: 40s, execs: 500000 (12000/sec), new interesting: 3 (total: 90)" \
    "$(grep -A1 '^  last statistics line before the expiry' "$st_dir/out.race" | tail -n 1)" \
    "the excused run prints the last statistics line, which is where a hang shows and a race does not"
  assert_eq "1" "$(grep -c '^exit status 1' "$st_dir/out.race" || true)" \
    "the fuzzer's own log is printed, not swallowed"

  stub_calls=0
  stub_races=99
  rc=0
  run_target ./stub FuzzStub 40s "$st_corpus" >"$st_dir/out.repeat" 2>&1 || rc=$?
  assert_eq "1" "$rc" "a repeated deadline signature fails the target rather than being excused again"
  assert_eq "2" "$stub_calls" "the retry is capped at max_attempts"
  assert_eq "1" "$(grep -c '^::error title=fuzz deadline signature repeated' "$st_dir/out.repeat" || true)" \
    "the second race says why the job is red rather than exhausting the loop in silence"

  # A build error or a panic is not a race and buys no second attempt. Without this the retry
  # policy could be widened to every verdict and nothing here would notice, because the stub had
  # no way to produce anything but a race or a crasher.
  stub_calls=0
  stub_races=0
  stub_panics=1
  rc=0
  run_target ./stub FuzzStub 40s "$st_corpus" >"$st_dir/out.other" 2>&1 || rc=$?
  stub_panics=0
  assert_eq "1" "$rc" "a failure that is neither a crasher nor a race fails the target"
  assert_eq "1" "$stub_calls" "a panic is failed on the first attempt and never re-run"
  assert_eq "1" "$(grep -c '^::error title=fuzz failed' "$st_dir/out.other" || true)" \
    "a failure of the third kind says the log is where to read the reason"

  # The assertion the whole script exists to keep honest: a crasher is never retried away.
  stub_calls=0
  stub_races=0
  stub_writes_crasher=1
  rc=0
  run_target ./stub FuzzStub 40s "$st_corpus" >"$st_dir/out.crash" 2>&1 || rc=$?
  assert_eq "1" "$rc" "a crasher fails the target"
  assert_eq "1" "$stub_calls" "a crasher is failed on the first attempt and never re-run"
  assert_eq "1" "$(grep -c '^::error title=fuzz crasher' "$st_dir/out.crash" || true)" \
    "the crasher annotation tells the reader to commit the input as a seed"

  # The first write into a corpus directory that does not exist yet. corpus_state treats a missing
  # directory as an empty listing on purpose, and this is the case that turns on it: a target with
  # no committed seeds has no directory at all until a crasher creates one, so reading the missing
  # directory as an error rather than as "nothing here yet" would lose the first finding of every
  # such target. Nothing above reaches it, because every case above ran against a directory the
  # self-test had already made.
  st_corpus="$st_dir/corpus-first-write"
  stub_calls=0
  stub_races=0
  stub_writes_crasher=1
  rc=0
  run_target ./stub FuzzStub 40s "$st_corpus" >"$st_dir/out.firstwrite" 2>&1 || rc=$?
  assert_eq "1" "$rc" "a crasher written where no corpus directory existed yet is still a crasher"
  assert_eq "1" "$stub_calls" "the first write into an absent corpus directory is not retried"

  # --- the main path, driven end to end against a `go` that is not Go ------------------------
  # Everything above stops at run_target. The lines that turn a failing target into a red JOB run
  # below this self-test's own exit, and no stub reaches them: the tally, the verdict, the
  # argument checks, and the one place this script actually shells out. Each of those was left
  # green by a mutation, including one that counted no failing target and exited 0 anyway
  # over a crasher. So the real entry point is run here as a subprocess, against a copy of itself
  # in a temporary tree, with a `go` on PATH that records its argv and reports a crasher. Still no
  # Go toolchain, no corpus and no fuzzing budget.
  mp="$tmpdir/mainpath"
  mkdir -p "$mp/scripts" "$mp/stubpkg" "$mp/bin"
  cp "${BASH_SOURCE[0]}" "$mp/scripts/fuzz-bounded.sh"
  # The crasher line goes to STDERR and the corpus is left untouched, so a run that stopped
  # merging stderr into the log would see a bare deadline line, excuse it, and call `go` twice.
  # That is what makes the argv assertion below cover the redirection as well as the flags.
  cat >"$mp/bin/go" <<'GO_SHIM'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$GO_SHIM_ARGV"
printf -- 'fuzz: elapsed: 1s, execs: 12 (12/sec), new interesting: 0 (total: 0)\n--- FAIL: FuzzStub (1.00s)\n    context deadline exceeded\n'
printf -- '    Failing input written to testdata/fuzz/FuzzStub/deadbeef\n' >&2
exit 1
GO_SHIM
  chmod +x "$mp/bin/go"

  : >"$mp/argv"
  rc=0
  GO_SHIM_ARGV="$mp/argv" PATH="$mp/bin:$PATH" \
    "$mp/scripts/fuzz-bounded.sh" ./stubpkg 1s FuzzStub >"$mp/out" 2>&1 || rc=$?
  assert_eq "1" "$rc" "a failing target makes the whole run exit non-zero"
  assert_eq "1" "$(grep -cF 'fuzz-bounded: ./stubpkg over 1 target(s), 1 attempt(s), 1 failing target(s)' "$mp/out" || true)" \
    "the failing target is counted and declared, rather than tallied as a clean run"
  assert_eq "1" "$(grep -c '^::error title=fuzz crasher' "$mp/out" || true)" \
    "the crasher reaches the job log through the real entry point too"
  assert_eq 'test ./stubpkg -run ^$ -fuzz ^FuzzStub$ -fuzztime 1s' "$(<"$mp/argv")" \
    "go is invoked once, with the budget, with unit tests suppressed and the target anchored"

  rc=0
  GO_SHIM_ARGV="$mp/argv" PATH="$mp/bin:$PATH" \
    "$mp/scripts/fuzz-bounded.sh" ./stubpkg 1s >"$mp/out.arity" 2>&1 || rc=$?
  assert_eq "1" "$rc" "a call with no target refuses rather than fuzzing nothing and passing"
  assert_eq "1" "$(grep -cF 'usage: scripts/fuzz-bounded.sh' "$mp/out.arity" || true)" \
    "the refusal for a missing target says what the arguments are"

  rc=0
  GO_SHIM_ARGV="$mp/argv" PATH="$mp/bin:$PATH" \
    "$mp/scripts/fuzz-bounded.sh" ./nosuchpkg 1s FuzzStub >"$mp/out.nopkg" 2>&1 || rc=$?
  assert_eq "1" "$rc" "a package that is not there refuses rather than reporting a clean fuzz pass"
  assert_eq "1" "$(grep -cF 'no package directory at nosuchpkg' "$mp/out.nopkg" || true)" \
    "the refusal for a missing package names the directory it looked for"

  if [[ "$fails" -gt 0 ]]; then
    echo "fuzz-bounded --self-test: $fails of $checks assertion(s) failed" >&2
    exit 1
  fi
  echo "fuzz-bounded --self-test: $checks assertions passed (the CI failure text is excused once and only once; a crasher, a panic, a wrapped deadline error and a deadline line with no --- FAIL are not excused at all; and the real entry point turns a failing target into a red job)"
  exit 0
fi

if [[ "$#" -lt 3 ]]; then
  echo "usage: scripts/fuzz-bounded.sh <pkg> <fuzztime> <target> [<target> ...]" >&2
  echo "       scripts/fuzz-bounded.sh --self-test" >&2
  exit 1
fi

pkg="$1"
budget="$2"
shift 2

pkg_dir="${pkg#./}"
if [[ ! -d "$repo_root/$pkg_dir" ]]; then
  echo "no package directory at $pkg_dir, so no target could be fuzzed" >&2
  exit 1
fi

for target in "$@"; do
  echo "::group::fuzz ${pkg} ${target} (${budget})"
  if ! run_target "$pkg" "$target" "$budget" "$repo_root/$pkg_dir/testdata/fuzz/$target"; then
    failures=$((failures + 1))
  fi
  echo "::endgroup::"
done

echo "fuzz-bounded: $pkg over $# target(s), $attempts attempt(s), $failures failing target(s)"
if [[ "$failures" -gt 0 ]]; then
  exit 1
fi
