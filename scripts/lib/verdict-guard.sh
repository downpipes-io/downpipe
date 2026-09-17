# shellcheck shell=bash
# verdict-guard.sh: the shared completion guard for this repository's SHELL entry points.
#
# WHY A SECOND FILE. scripts/lib/verdict-guard.mjs is shared verbatim with website and control-plane and
# arms node entry points. It cannot arm a bash gate, and this repository is a Go repository whose gates
# are bash scripts driven by make targets, so the node guard alone would have covered exactly one of
# them. This file is the same contract in bash: arm on source, declare before exit, and force a non-zero
# exit where the declaration never happened.
#
# THE CLASS IT CLOSES, and it has already been measured HERE. downpipe/scripts/coverage-gate.sh had
# `awk ...` on its own line followed by `awk_status=$?` on the next. Under `set -e`, which that script
# sets and which the CI step's own `bash -e` sets again, a bare command exiting non-zero terminates the
# script where it stands, so the assignment and every line below it were unreachable on exactly the run
# they exist for: the job exited 1 having printed nine near-identical rows and no verdict, and the
# four-letter difference between "ok  " and "FAIL" on one of them was the entire statement of the reason.
# That is the same shape the node guard was written for, reached through `set -e` rather than through a
# promise that never settles.
#
# WHY AN EXIT TRAP IS ENOUGH IN BASH. A bash EXIT trap runs on an explicit `exit`, on the script falling
# off its last line, and on a `set -e` termination, and inside the trap an `exit N` replaces the status
# the script was going to report. So one trap catches every route that reaches the end of the process:
#   - a `set -e` termination part way through, before the verdict (the measured case above);
#   - an early `exit 0` before the verdict;
#   - a `return` from the last function with the tally never reached;
#   - a pipeline whose status was read from the wrong end.
# It does NOT catch SIGKILL, and nothing in a shell can. A gate killed outright reports the signal, which
# is already a non-zero status, so the case the guard exists for does not arise there.
#
# USAGE, three lines:
#   . "$(dirname "${BASH_SOURCE[0]}")/lib/verdict-guard.sh"   # sourcing this ARMS the guard
#   ...
#   echo "example: $count item(s), $failures finding(s)"
#   verdict_reached "$failures" "$count"                      # declare the verdict you just printed
#
# Where a precondition is genuinely absent, declare the skip instead, with its reason:
#   verdict_skipped "cyclonedx-gomod is not installed"        # add `require` to make the skip a failure
#
# DO NOT INSTALL YOUR OWN `trap ... EXIT` after sourcing this. A second EXIT trap REPLACES this one and
# silently disarms the guard, which is why scripts/verdict-guard-gate.mjs treats a competing EXIT trap in
# an enrolled shell entry point as a finding. Where a script needs cleanup, define a function called
# verdict_guard_cleanup and this file will run it first.

__vg_declared=0
__vg_refusals=0
__vg_entry="${BASH_SOURCE[1]:-$0}"

# verdict_reached <failures> <checks>
#
# failures: how many checks failed, or how many units of work were not completed. A positive count sets
#   the exit status to 1 even where the caller forgets its own `exit 1`, because "printed N FAILURE(S)
#   and exited 0" is the same false green by a shorter route.
# checks: how much was actually checked. Zero is a failure: a gate that checked nothing is not one that
#   passed. It is REQUIRED here, unlike in the node guard, because a shell script has no cheap way to
#   count the bytes it wrote and so has no floor to fall back on.
verdict_reached() {
  __vg_declared=1
  local failures="${1:-}" checks="${2:-}"
  if [[ ! "$failures" =~ ^[0-9]+$ ]]; then
    printf '\nVERDICT GUARD: %s declared a verdict with a failure count of "%s", which is not a number.\n  Forcing exit 1.\n' "$__vg_entry" "$failures" >&2
    __vg_refusals=1
    return 0
  fi
  if [[ ! "$checks" =~ ^[0-9]+$ || "$checks" -le 0 ]]; then
    printf '\nVERDICT GUARD: %s declared a verdict after doing %s unit(s) of work.\n  Nothing was checked, so there was nothing to pass. Forcing exit 1.\n' "$__vg_entry" "${checks:-0}" >&2
    __vg_refusals=1
    return 0
  fi
  # One canonical line, printed by the guard rather than by each gate, so the log-reading half of a
  # verification has a fixed anchor too. Grep this with a FIXED STRING, never a regex: a verification
  # grep of `(^|[^a-zA-Z])FAIL` matched nothing under BSD grep on macOS while plain `grep FAIL` found 41
  # lines on the same failing log, so a log-reading check can pass on a failing run just as quietly as an
  # exit code can. Use `grep -F "VERDICT: FAIL"`.
  local outcome="PASS"
  [[ "$failures" -eq 0 ]] || outcome="FAIL"
  printf 'VERDICT: %s failures=%s checks=%s entry=%s\n' "$outcome" "$failures" "$checks" "$__vg_entry"
  [[ "$failures" -eq 0 ]] || __vg_refusals=1
}

# verdict_skipped <reason> [require]
#
# A skip is a real verdict and must be declared like any other, because "exits 0 having done nothing" is
# the same false green whether the cause is a `set -e` termination or a missing precondition. It does NOT
# force a non-zero exit by default: some preconditions here are deliberately opt-in, such as a tool the
# current environment has not installed. Pass `require` as the second argument where the precondition is
# mandatory in the environment the caller is running in, and the skip then exits 1.
verdict_skipped() {
  __vg_declared=1
  local reason="${1:-no reason given}" mandatory="${2:-}"
  printf '\nVERDICT SKIPPED: %s: %s\n' "$__vg_entry" "$reason"
  if [[ "$mandatory" == "require" ]]; then
    printf '  the precondition was declared mandatory here, so the skip is a failure.\n' >&2
    __vg_refusals=1
  fi
}

__vg_on_exit() {
  local code=$?
  trap - EXIT
  # Cleanup first, so a gate that needs to remove a temporary tree still can without installing its own
  # EXIT trap and disarming the guard in the process.
  if declare -F verdict_guard_cleanup >/dev/null 2>&1; then verdict_guard_cleanup || true; fi
  if [[ "$__vg_declared" -eq 1 ]]; then
    # A refused verdict has to STICK. An explicit `exit 0` on the line after the declaration would
    # otherwise carry the status, which is the same false green arriving through the guard itself.
    if [[ "$__vg_refusals" -gt 0 && "$code" -eq 0 ]]; then
      printf '\nVERDICT GUARD: %s had its verdict refused and then exited 0.\n  The refusal is re-applied here.\n' "$__vg_entry" >&2
      exit 1
    fi
    exit "$code"
  fi
  # stderr, so a caller that reads this gate's stdout still sees the non-zero status without the message
  # landing in the data.
  printf '\nVERDICT GUARD: %s reached process exit with code %s without declaring a verdict.\n  The verdict was never reached, so nothing in this run was capable of failing.\n  Causes seen in this repository: a `set -e` termination before the tally, an early exit 0, a\n  pipeline whose status was read from the wrong end, or a tally guarded by a condition that never held.\n' "$__vg_entry" "$code" >&2
  if [[ "$code" -eq 0 ]]; then
    printf '  Forcing exit 1: a silent exit 0 here is a false green.\n' >&2
    exit 1
  fi
  printf '  Leaving the non-zero exit code as it stands.\n' >&2
  exit "$code"
}

trap __vg_on_exit EXIT
