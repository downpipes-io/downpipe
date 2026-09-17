#!/usr/bin/env bash
# Confirms the CI Success job actually gates on every job in the workflow, and that a job
# which did not run cannot read as a pass.
#
# WHY THIS EXISTS. CI here is a fan-out: build-test, coverage, lint, govulncheck, fuzz,
# schema-validate and vectors-listing run in parallel, and a single ci-success job with
# `if: always()` decides the run. That is the right shape, and it is better than the sibling
# repos, whose gate suites are one `&&` chain per repo: a measurement of all
# four chains found 170 of 591 members were never reached, because an early red member fails
# the chain before the rest of it runs. A fan-out has no such ordering.
#
# It has two other ways to lie, and this script closes both.
#
#   1. `needs:` is a hand-maintained enumeration. Add a job and forget to list it, and
#      ci-success passes without it, forever, and nothing says so. Enumerating is exactly
#      how a gate goes missing.
#   2. `contains(needs.*.result, 'failure')` does not catch 'skipped'. A job that never ran
#      is not a job that passed, and a required job can be skipped by its own `if:` or by a
#      skipped dependency. Silence has to fail, or a gate can be switched off invisibly.
#
# Three checks, all of which must hold:
#   1. Every job id in ci.yml other than ci-success appears in ci-success's `needs:` list.
#   2. Every name in that `needs:` list is a real job id, so a renamed job cannot leave a
#      dead entry behind that gates on nothing.
#   3. ci-success's failure expression names 'skipped' as well as 'failure' and 'cancelled'.
#
# It reads the workflow and nothing else; it never edits it, and it exits non-zero on drift.

set -euo pipefail

# Sourcing this ARMS the completion guard: every route out of this script must declare a verdict or the
# guard forces a non-zero exit.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/verdict-guard.sh"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workflow="$repo_root/.github/workflows/ci.yml"
gate_job="ci-success"

if [[ ! -f "$workflow" ]]; then
  echo "::error::no workflow at $workflow, so there is nothing to check" >&2
  verdict_skipped "no workflow at $workflow, so no job could be read" require
  exit 1
fi

# Job ids are the two-space-indented keys under the top-level `jobs:` block.
# Read with a while loop rather than mapfile: mapfile is bash 4, and macOS ships bash 3.2,
# so a maintainer running this locally would otherwise get a missing-command error instead
# of a verdict.
jobs=()
while IFS= read -r job_id; do
  jobs+=("$job_id")
done < <(awk '
  /^jobs:[[:space:]]*$/ { in_jobs = 1; next }
  /^[^[:space:]#]/      { in_jobs = 0 }
  in_jobs && /^  [a-zA-Z0-9_-]+:[[:space:]]*$/ {
    line = $0
    sub(/^  /, "", line)
    sub(/:[[:space:]]*$/, "", line)
    print line
  }
' "$workflow")

if [[ ${#jobs[@]} -lt 2 ]]; then
  echo "::error::found ${#jobs[@]} job(s) in $workflow. A workflow this small has not proven anything, and this check cannot grade it" >&2
  verdict_skipped "found ${#jobs[@]} job(s) in $workflow, too few to grade" require
  exit 1
fi

found_gate=0
for job in "${jobs[@]}"; do
  [[ "$job" == "$gate_job" ]] && found_gate=1
done
if [[ $found_gate -eq 0 ]]; then
  echo "::error::$workflow has no \"$gate_job\" job, so the job that decides the run has vanished rather than passed" >&2
  # A real finding rather than a skip: the jobs were read, and what they say is that the gate job is
  # gone. The count is the number of jobs actually read out of the workflow.
  verdict_reached 1 "${#jobs[@]}"
  exit 1
fi

# The gate job's needs list, as written on its own `needs:` line.
needs_line="$(awk -v gate="$gate_job" '
  $0 == "  " gate ":" { in_gate = 1; next }
  in_gate && /^  [a-zA-Z0-9_-]+:[[:space:]]*$/ { in_gate = 0 }
  in_gate && /^[[:space:]]*needs:/ { print; exit }
' "$workflow")"

if [[ -z "$needs_line" ]]; then
  echo "::error::the \"$gate_job\" job has no needs: line, so it waits for nothing and its pass means nothing" >&2
  verdict_reached 1 "${#jobs[@]}"
  exit 1
fi

needs_body="${needs_line#*needs:}"
needs_body="${needs_body//[\[\],]/ }"
read -r -a needs <<<"$needs_body"

status=0

# Check 1: every job other than the gate job is required by it.
for job in "${jobs[@]}"; do
  [[ "$job" == "$gate_job" ]] && continue
  listed=0
  for need in "${needs[@]}"; do
    [[ "$need" == "$job" ]] && listed=1
  done
  if [[ $listed -eq 0 ]]; then
    echo "::error::job \"$job\" is not in $gate_job's needs list, so the run can go green without it" >&2
    status=1
  fi
done

# Check 2: every needs entry is a real job.
for need in "${needs[@]}"; do
  real=0
  for job in "${jobs[@]}"; do
    [[ "$need" == "$job" ]] && real=1
  done
  if [[ $real -eq 0 ]]; then
    echo "::error::$gate_job needs \"$need\", which is not a job in this workflow, so that entry gates on nothing" >&2
    status=1
  fi
done

# Check 3: a job that did not run must not read as a pass.
#
# THE COMMENTS ARE DROPPED AND THE WHOLE CALL IS MATCHED, because neither was true and the
# check was blind to the one state it was written for. It asked whether the quoted word
# appeared anywhere in the gate job's block, and the block's own explanatory comment quotes
# 'skipped' in order to explain why it is there. Deleting `|| contains(needs.*.result,
# 'skipped')` from the expression that decides the run therefore left this script printing
# "failure, cancelled and skipped all fail the run", proven against this workflow, while a
# skipped required job read as a pass again. That is the defect this script exists to stand
# over, and the comment describing the fix was what kept satisfying the check after the fix
# was gone.
#
# So comment lines are removed first, and each state has to appear inside a real
# contains(needs.*.result, '<state>') call rather than merely somewhere in the block. A
# quoted word in prose, a job name or an echo string no longer counts as a gate.
gate_body="$(awk -v gate="$gate_job" '
  $0 == "  " gate ":" { in_gate = 1; next }
  in_gate && /^  [a-zA-Z0-9_-]+:[[:space:]]*$/ { in_gate = 0 }
  in_gate && /^[[:space:]]*#/ { next }
  in_gate { print }
' "$workflow")"

for result in failure cancelled skipped; do
  if ! grep -qE "contains\(needs\.\*\.result,[[:space:]]*'$result'\)" <<<"$gate_body"; then
    echo "::error::$gate_job's result expression has no contains(needs.*.result, '$result'), so a required job in that state reads as a pass" >&2
    status=1
  fi
done

# Check 4: a STEP that did not run must not read as a pass either.
#
# Checks 1 to 3 are job-scoped, and that was the whole of this script's population until a step-level
# `if:` was put to it. Attaching `if: github.ref == 'refs/heads/release-only'` to the coverage gate step
# switches off the only enforcement of the per-package coverage floors; the job's other steps still run,
# so the job succeeds, ci-success sees 'success' rather than 'skipped', and the run is green with the
# floor never applied. Reproduced against every guard in this repository: all seven exited 0.
# A gate switched off one level below the one this script was reading is the same defect it exists to
# stand over.
#
# The rule is that every condition in this workflow may only BROADEN. `always()` and `!cancelled()` make
# a step or job run in more circumstances than the default, which is what the ten conditions in this
# workflow are for: each gate step is a separate verdict and none may be hidden by an earlier failure.
# Anything else narrows, and a narrowed gate is a gate that can be absent from a green run. Measured
# before it was written: all 11 conditions in ci.yml today are broadening, so this flags nothing that is
# already here. `continue-on-error` is the same false green by another spelling and is refused outright.
#
# Comment lines are dropped first, for the reason check 3 records: this file's own prose quotes the
# conditions it is about, and a check that reads a comment as configuration is satisfied by the
# description of the thing rather than by the thing.
conditions="$(awk '
  /^jobs:[[:space:]]*$/ { in_jobs = 1; next }
  /^[^[:space:]#]/      { in_jobs = 0 }
  !in_jobs { next }
  /^[[:space:]]*#/ { next }
  {
    line = $0
    sub(/[[:space:]]+#.*$/, "", line)
    if (line ~ /^[[:space:]]*(-[[:space:]]+)?if:/) { sub(/^[[:space:]]*(-[[:space:]]+)?if:[[:space:]]*/, "", line); print NR "\tif\t" line }
    else if (line ~ /^[[:space:]]*(-[[:space:]]+)?continue-on-error:/) { sub(/^[[:space:]]*(-[[:space:]]+)?continue-on-error:[[:space:]]*/, "", line); print NR "\tcontinue-on-error\t" line }
  }
' "$workflow")"

condition_count=0
while IFS=$'\t' read -r lineno kind expr; do
  [[ -z "${kind:-}" ]] && continue
  condition_count=$((condition_count + 1))
  if [[ "$kind" == "continue-on-error" ]]; then
    echo "::error::$workflow line $lineno sets continue-on-error: $expr. A step whose failure does not fail the job is a gate that cannot fail, which is the state this script exists to refuse" >&2
    status=1
    continue
  fi
  # Strip the ${{ }} wrapper, quotes and all whitespace, then compare against the two broadening forms.
  # Parameter expansion rather than sed: BSD sed reads `\{\{` as an interval and errors out, so the
  # portable spelling is the shell's own. (The completion guard caught that immediately: the script
  # exited 1 with no verdict and was told so, rather than reading as a finding.)
  normalised="${expr//\$\{\{/}"
  normalised="${normalised//\}\}/}"
  normalised="$(printf '%s' "$normalised" | tr -d '[:space:]')"
  if [[ "$normalised" != "always()" && "$normalised" != "!cancelled()" ]]; then
    echo "::error::$workflow line $lineno carries a NARROWING condition: if: $expr" >&2
    echo "::error::  Only always() and !cancelled() are allowed here, because they broaden. Anything else lets a gate be absent from a green run: the step is skipped, its job still succeeds, and ci-success sees 'success' rather than 'skipped'." >&2
    status=1
  fi
done <<<"$conditions"

if [[ "$condition_count" -eq 0 ]]; then
  # Ten of these are load-bearing today. None at all means the extraction has stopped extracting, and a
  # check that found nothing to look at has not looked.
  echo "::error::no if: or continue-on-error condition was extracted from $workflow at all, so check 4 compared nothing. The extraction has broken" >&2
  verdict_skipped "no condition was extracted from $workflow, so the step-level check compared nothing" require
  exit 1
fi

# The count is the number of jobs actually read out of the workflow, which is the population every check
# above was made over. The floor near the top already refuses a workflow too small to grade.
if [[ $status -ne 0 ]]; then
  echo "ci gate completeness: FAIL" >&2
  verdict_reached "$status" "${#jobs[@]}"
  exit 1
fi

echo "ci gate completeness: ${#jobs[@]} job(s), $gate_job requires all ${#needs[@]} of the others, and failure, cancelled and skipped all fail the run."
echo "ci gate completeness: $condition_count condition(s) read across those jobs, every one of them broadening, and no continue-on-error anywhere."
verdict_reached 0 "${#jobs[@]}"
