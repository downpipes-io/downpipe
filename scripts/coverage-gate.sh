#!/usr/bin/env bash
# Per-package statement-coverage gate.
#
# Coverage is aggregated from the profile's STATEMENT BLOCKS, not from `go tool cover
# -func` (whose rows are per function, so summing them is not a package total). Every
# package that `go list` reports must appear in the profile: a package with no tests at
# all must fail loudly rather than silently escape the gate.
#
# internal/crypto carries the highest floor because it is the security-critical core;
# every other package shares the general floor.
set -euo pipefail


# --self-test proves this gate can FAIL AND SAY SO, which is the property that was broken.
#
# The gate exited 1 correctly on a below-floor package and printed nothing that read as a
# verdict: nine near-identical rows, one of them starting "FAIL" instead of "ok  ", and then
# the job ended. The summary line meant to close it was unreachable, because a bare `awk`
# under `set -e` terminates the script before `awk_status=$?` on the next line.
#
# An exit-code assertion could not have caught that: the exit code was already 1, before and
# after. So the self-test asserts on the OUTPUT, and pairs each assertion with a control that
# a passing profile does NOT print the same thing.
if [[ "${1:-}" == "--self-test" ]]; then
  bed="$(mktemp -d)"
  trap 'rm -rf "$bed"' EXIT
  mod="$(go list -m)"
  fails=0
  # Counted at the assertion rather than written into the summary line. It used to say "14 assertions
  # passed" as a literal, so deleting an assertion left the line claiming a number the run no longer did.
  checked=0
  check() { # check <description> <haystack> <needle> <want-present:0|1>
    local desc="$1" hay="$2" needle="$3" want="$4" got=0
    checked=$((checked + 1))
    [[ "$hay" == *"$needle"* ]] && got=1
    if [[ "$got" != "$want" ]]; then
      echo "coverage-gate --self-test FAIL: $desc (wanted present=$want, got $got) for: $needle" >&2
      fails=$((fails + 1))
    fi
  }
  # Two profiles over the same synthetic package set: one where every package clears the
  # floor, one where a single package falls one statement short. Every package `go list`
  # reports is present in both, so the absence check is not what is under test here.
  # 100 statements per package, so a one-statement difference is 1% and the margin band is
  # expressible. The first package listed is the one whose covered count varies; every other
  # package sits comfortably at 100%.
  first="$(go list ./... | head -1)"
  write_profile() { # write_profile <path> <covered-of-100-for-the-first-package>
    local out="$1" hit="$2" i=0 covered=0
    echo "mode: set" > "$out"
    for pkg in $(go list ./...); do
      covered=100
      [[ "$pkg" == "$first" ]] && covered="$hit"
      for ((i = 1; i <= 100; i++)); do
        local c=0
        (( i <= covered )) && c=1
        echo "$pkg/selftest.go:$i.1,$i.2 1 $c" >> "$out"
      done
    done
  }
  # The zero-denominator profile. The first package's blocks all carry zero statements, which
  # is what `go test -coverpkg=./...` emits for a package holding declarations and one empty
  # function body; every other package sits at 100%, so the only thing under test is the zero.
  # The offender sorts FIRST, so a truncated report loses every other row and the assertion
  # below that the last package still appears is what catches that.
  write_zero_profile() { # write_zero_profile <path>
    local out="$1" i=0
    echo "mode: set" > "$out"
    for pkg in $(go list ./...); do
      for ((i = 1; i <= 100; i++)); do
        if [[ "$pkg" == "$first" ]]; then
          echo "$pkg/selftest.go:$i.1,$i.2 0 0" >> "$out"
        else
          echo "$pkg/selftest.go:$i.1,$i.2 1 1" >> "$out"
        fi
      done
    done
  }
  # The ABSENCE profile: every package but the last is present, and the first sits one statement above
  # its floor, so a single run carries both an absence failure and the narrow-margin advisory. That
  # combination is the one that put the word "passing" one line above "FAILED".
  write_absence_profile() { # write_absence_profile <path> <covered-of-100-for-the-first-package>
    local out="$1" hit="$2" i=0 covered=0 last_pkg
    last_pkg="$(go list ./... | LC_ALL=C sort | tail -1)"
    echo "mode: set" > "$out"
    for pkg in $(go list ./...); do
      [[ "$pkg" == "$last_pkg" ]] && continue
      covered=100
      [[ "$pkg" == "$first" ]] && covered="$hit"
      for ((i = 1; i <= 100; i++)); do
        local c=0
        (( i <= covered )) && c=1
        echo "$pkg/selftest.go:$i.1,$i.2 1 $c" >> "$out"
      done
    done
  }
  write_profile "$bed/pass.out" 100  # comfortable: 14 statements above the 85% floor
  write_profile "$bed/fail.out" 80   # 80%, one clear step below the floor
  write_profile "$bed/narrow.out" 86 # over the floor by exactly one statement
  write_zero_profile "$bed/zero.out"
  write_absence_profile "$bed/absence.out" 86

  pass_out="$("$0" "$bed/pass.out" 2>&1)"; pass_code=$?
  fail_out="$("$0" "$bed/fail.out" 2>&1)" || true
  "$0" "$bed/fail.out" >/dev/null 2>&1 && fail_code=0 || fail_code=$?

  check "a clean profile exits 0" "$pass_code" "0" 1
  check "a clean profile says so" "$pass_out" "every package meets its floor" 1
  check "a clean profile prints no failure verdict" "$pass_out" "coverage-gate: FAILED" 0
  check "a below-floor profile exits 1" "$fail_code" "1" 1
  check "a below-floor profile marks the row" "$fail_out" "FAIL " 1
  # The assertion the whole self-test exists for. It was false while the exit code was right.
  check "a below-floor profile prints a closing VERDICT" "$fail_out" "coverage-gate: FAILED, below the floor" 1
  check "the verdict names the package" "$fail_out" "${first#"$mod"/}" 1
  check "the verdict names the shortfall" "$fail_out" "below its floor of 85%" 1
  check "a below-floor profile does not also claim success" "$fail_out" "every package meets its floor" 0
  narrow_out="$("$0" "$bed/narrow.out" 2>&1)"; narrow_code=$?
  check "a narrow-margin profile still exits 0" "$narrow_code" "0" 1
  check "a narrow-margin profile says it is narrow" "$narrow_out" "NARROW MARGIN (advisory, not the verdict)" 1
  check "a narrow-margin profile still says it met the floor" "$narrow_out" "every package meets its floor" 1
  # The control: a comfortable profile must NOT carry the advisory, or the warning means
  # nothing and will be ignored the one time it matters.
  check "a comfortable profile carries no narrow-margin advisory" "$pass_out" "NARROW MARGIN" 0

  # THE SKIM-READ HAZARD, which was a real property of this script's output and not a hypothetical. On an
  # ABSENCE failure the advisory is printed by awk, which has nothing of its own to fail on, so it landed
  # above the shell's closing verdict. The advisory opened with the word "passing", so a reader scanning a
  # RED log met "coverage-gate: passing" one line before "coverage-gate: FAILED". These assertions hold
  # the output to the rule that nothing on a failing run may read as a pass.
  absence_out="$("$0" "$bed/absence.out" 2>&1)" || true
  "$0" "$bed/absence.out" >/dev/null 2>&1 && absence_code=0 || absence_code=$?
  check "an absent package fails the gate" "$absence_code" "1" 1
  # THE ASSERTION THAT DID NOT ASSERT. This read `"absent from the coverage profile"`, which the CLOSING
  # SUMMARY line also contains ("one or more packages are absent from the coverage profile (listed
  # above)"), and that line names no package at all. Rewriting the per-package row to say nothing
  # identifiable left the self-test at 28 of 28, proven by mutation. The row is the only
  # thing that tells an operator WHICH package has no coverage, so the assertion names it.
  absent_pkg="$(go list ./... | LC_ALL=C sort | tail -1)"
  check "the absent package is named on its own row" "$absence_out" "FAIL ${absent_pkg#"$mod"/}: absent from the coverage profile" 1
  check "a run with every package present names no absent package" "$pass_out" "absent from the coverage profile" 0
  check "an absent package still gets the narrow-margin advisory" "$absence_out" "NARROW MARGIN (advisory, not the verdict)" 1
  check "a failing run says the word passing nowhere" "$absence_out" "passing" 0
  check "a failing run does not claim every package met its floor" "$absence_out" "every package meets its floor" 0
  check "a failing run closes on the verdict" "$absence_out" "coverage-gate: FAILED: one or more packages are absent" 1

  # THE ZERO-DENOMINATOR CASE, which reached this gate as `awk: division by zero` and a report
  # cut off after three rows. The exit code was already 1, so only assertions on the OUTPUT can
  # tell the fixed gate from the broken one.
  last="$(go list ./... | LC_ALL=C sort | tail -1)"
  zero_out="$("$0" "$bed/zero.out" 2>&1)" || true
  "$0" "$bed/zero.out" >/dev/null 2>&1 && zero_code=0 || zero_code=$?
  check "a zero-statement package fails the gate" "$zero_code" "1" 1
  check "a zero-statement package does not abort the report" "$zero_out" "division by zero" 0
  check "a zero-statement package names the reason" "$zero_out" "contributes no coverable statements" 1
  check "a zero-statement package names the offender" "$zero_out" "${first#"$mod"/}" 1
  check "a zero-statement package prints the closing VERDICT" "$zero_out" "coverage-gate: FAILED, below the floor" 1
  # The truncation assertion: the offender sorts first, so the LAST package appearing proves
  # every row after it was still read and reported.
  check "a zero-statement package still reports every later package" "$zero_out" "${last#"$mod"/}" 1
  check "a zero-statement package does not also claim success" "$zero_out" "every package meets its floor" 0
  # The control: an ordinary clean profile must not carry the zero-denominator finding.
  check "a clean profile carries no zero-statement finding" "$pass_out" "contributes no coverable statements" 0

  # THE go list FLOOR, which nothing held. It is the check that stops this gate reporting on a package
  # set it never enumerated: `go list` outside the module prints an error and no packages, the loop above
  # reads nothing, and every per-package comparison is then made over an empty set. Proven live by
  # invoking the gate from a directory outside the module, and proven unasserted by mutation on
  # : setting the comparison to `-lt 0` so it can never trip left the self-test green.
  floor_out="$(PACKAGE_FLOOR=1000000 "$0" "$bed/pass.out" 2>&1)" || true
  PACKAGE_FLOOR=1000000 "$0" "$bed/pass.out" >/dev/null 2>&1 && floor_code=0 || floor_code=$?
  check "a package count under the floor fails" "$floor_code" "1" 1
  check "a package count under the floor says so" "$floor_out" "fewer than the floor of 1000000" 1
  check "a package count under the floor does not also claim success" "$floor_out" "every package meets its floor" 0
  # The control: the ordinary run must not carry the floor finding, or it means nothing.
  check "an ordinary run carries no package-floor finding" "$pass_out" "fewer than the floor of" 0

  # Ordering is by package name, so two runs of the same profile produce the same log and
  # two runs of different profiles can be diffed. awk iterates a map in hash order, which is
  # stable for one input and gives no ordering guarantee ACROSS inputs, so comparing a run
  # against itself proves nothing. This asserts the rows really are sorted.
  rows="$(printf '%s\n' "$pass_out" | awk '/^(ok  |FAIL) /{print $2}')"
  checked=$((checked + 1))
  if [[ "$rows" != "$(printf '%s\n' "$rows" | LC_ALL=C sort)" ]]; then
    echo "coverage-gate --self-test FAIL: package rows are not in sorted order:" >&2
    printf '%s\n' "$rows" >&2
    fails=$((fails + 1))
  fi

  if (( fails > 0 )); then
    echo "coverage-gate --self-test: $fails of $checked assertion(s) failed" >&2
    exit 1
  fi
  echo "coverage-gate --self-test: $checked assertions passed (a failing gate names its verdict, a narrow one says so without reading as one, a comfortable one says neither, and nothing on a failing run reads as a pass)"
  exit 0
fi

profile="${1:-coverage.out}"
crypto_floor="${CRYPTO_FLOOR:-90}"
# How close to its floor a passing package may sit before the gate says so out loud. Advisory
# only; it never changes the verdict.
margin_stmts="${MARGIN_STMTS:-5}"
floor="${FLOOR:-85}"
module="$(go list -m)"

if [[ ! -s "$profile" ]]; then
  echo "coverage-gate: no profile at $profile" >&2
  # No profile means no package was measured at all, so this is a mandatory skip rather than a counted
  # failure that would imply the packages were read and found wanting.
  exit 1
fi

# The "every package must appear" check is an ABSENCE, and an absence has to be shown to have
# been looked for. `set -euo pipefail` does not reach into a process substitution: if `go list`
# fails, for a build break in any package or a broken toolchain, the loop reads nothing, missing
# stays 0, and this check passes having examined no package at all. The floor is what makes the
# check say something, and it is a floor rather than an exact count so that adding a package is
# not a gate failure while REMOVING every package still is.
package_floor="${PACKAGE_FLOOR:-9}"

missing=0
listed=0
while read -r pkg; do
  listed=$((listed + 1))
  if ! grep -q "^${pkg}/" "$profile"; then
    echo "FAIL ${pkg#"$module"/}: absent from the coverage profile (no tests?)"
    missing=1
  fi
done < <(go list ./...)

if [[ $listed -lt $package_floor ]]; then
  echo "coverage-gate: go list reported $listed package(s), fewer than the floor of $package_floor. The per-package check below has not looked at what it claims to cover; fix the build or the module before reading this gate's verdict" >&2
  exit 1
fi

# Blocks are DEDUPLICATED by their source range before aggregation. With -coverpkg every
# test binary emits a row for every instrumented block, so the same block appears many
# times: summing rows would multiply the statement count and bury the real ratio. A block
# is counted once, and counted covered when ANY test binary executed it, which is exactly
# the question the gate asks.
if awk -v module="$module/" -v crypto_floor="$crypto_floor" -v floor="$floor" -v margin="$margin_stmts" '
  NR == 1 { next }                        # skip the "mode:" header
  {
    key = $1                              # file.go:startLine.col,endLine.col
    nstmt[key] = $2
    if ($3 > 0) hit[key] = 1
  }
  END {
    for (key in nstmt) {
      split(key, f, ":")
      path = f[1]
      n = split(path, p, "/")
      pkg = ""
      for (i = 1; i < n; i++) pkg = pkg p[i] "/"
      sub(module, "", pkg)
      sub(/\/$/, "", pkg)
      total[pkg] += nstmt[key]
      if (key in hit) covered[pkg] += nstmt[key]
    }
    fail = 0
    reasons = ""
    # Sorted so the report is stable run to run. awk `for (k in arr)` is hash order, so
    # the same profile printed its nine rows in a different order every run and a reader
    # comparing two logs could not diff them.
    n = 0
    for (k in total) pkgs[++n] = k
    for (i = 1; i < n; i++)
      for (j = i + 1; j <= n; j++)
        if (pkgs[j] < pkgs[i]) { t = pkgs[i]; pkgs[i] = pkgs[j]; pkgs[j] = t }
    for (i = 1; i <= n; i++) {
      k = pkgs[i]
      thr = (k == "internal/crypto") ? crypto_floor : floor
      # ZERO DENOMINATOR. A package whose every block carries zero statements, which a package
      # of declarations plus one empty function body really produces, has nothing to divide by,
      # and the division aborted the whole awk with "awk: division by zero" after three of ten
      # rows: the report was truncated, the closing verdict never printed, and every package
      # sorting after the offender went unread. The run still exited 1, so nothing passed that
      # should not have, but the reason a reader needs was not in the log. It fails here for the
      # same reason an absent package fails above: a floor that cannot be measured cannot be met.
      if (total[k] == 0) {
        printf "%s %-22s %7s  (floor %d%%, 0/0 stmts)\n", "FAIL", k, "n/a", thr
        fail = 1
        reasons = reasons sprintf("  %s contributes no coverable statements, so its floor of %d%% cannot be measured\n", k, thr)
        continue
      }
      pct = 100 * covered[k] / total[k]
      ok = (pct + 1e-9 >= thr)
      printf "%s %-22s %6.2f%%  (floor %d%%, %d/%d stmts)\n", ok ? "ok  " : "FAIL", k, pct, thr, covered[k], total[k]
      if (!ok) {
        fail = 1
        reasons = reasons sprintf("  %s is at %.2f%%, below its floor of %d%% (%d of %d statements covered; %d more needed)\n", k, pct, thr, covered[k], total[k], int(total[k] * thr / 100) + 1 - covered[k])
      } else {
        # NARROW MARGIN, ANNOUNCED WHILE IT IS STILL A PASS. A package sitting one statement
        # above its floor reddens main on the next commit that adds an untested line, and the
        # first anyone hears of it is a failed job on an unrelated change. This says so in
        # advance. It is advisory and never fails the gate: the floor is the floor.
        need = int(total[k] * thr / 100) + 1
        spare = covered[k] - need
        if (spare >= 0 && spare <= margin)
          narrow = narrow sprintf("  %s is %d statement(s) above its floor of %d%% (%d of %d covered, %d needed)\n", k, spare, thr, covered[k], total[k], need)
      }
    }
    # THE VERDICT, NAMED. A FAIL row is four characters different from an ok row and sits
    # in the middle of nine near-identical lines, so a reader scanning a CI log for why the
    # job went red finds nothing that looks like an answer. This says it at the end, where
    # a verdict belongs, and names the package and the shortfall.
    # On STDOUT, deliberately. The CI step pipes this through `tee coverage.txt` and uploads
    # that file as the run artefact, so a verdict written to stderr would reach the log and
    # never the record. The success line has always been on stdout; the failure verdict has
    # to live in the same place or the artefact says nothing about why the job went red.
    if (fail) printf "coverage-gate: FAILED, below the floor:\n%s", reasons
    # THE ADVISORY MUST NOT READ AS THE VERDICT. It used to open "coverage-gate: passing, but NARROW",
    # and on an ABSENCE failure, where a package is missing from the profile entirely, awk has nothing of
    # its own to fail on, so that line printed above the closing "FAILED: one or more packages are
    # absent" that the shell writes. The verdict was still last and still correct, but a reader scanning a
    # red log for the reason met the word "passing" one line before it, on a line opening "coverage-gate:",
    # which is the one prefix that reads like this gate speaking. A message that can be skim-read as the
    # opposite of the verdict is the same defect as a gate reporting the wrong one, arriving through the
    # reader rather than through the exit code. It leads with what it is now, and says outright that it is
    # not the verdict. NOTE FOR ANYONE EDITING THIS AWK PROGRAM: it is inside single quotes, so an
    # apostrophe anywhere in here, even in a comment, ends the quoting and breaks the script.
    else if (narrow != "") printf "coverage-gate: NARROW MARGIN (advisory, not the verdict). The next untested statement in these packages reddens the gate:\n%s", narrow
    exit fail
  }
' "$profile"; then
  awk_status=0
else
  awk_status=$?
fi

# THE STATUS HAS TO BE CAPTURED INSIDE A CONDITIONAL. It was `awk ... ` on its own line
# followed by `awk_status=$?`, and under `set -e` (which this script sets, and which the CI
# step's own `bash -e` sets again) a bare command exiting non-zero terminates the script
# where it stands. So the assignment and every line below it were UNREACHABLE on exactly
# the run they exist for: the job exited 1 having printed nine near-identical rows and no
# verdict, and the four-letter difference between "ok  " and "FAIL" on one of them was the
# entire statement of the reason.
# `listed` is the number of packages go list actually reported and this gate then looked for in the
# profile, which is the population every floor decision was made over. The package_floor check above
# already refuses a run that listed too few, and the guard refuses a zero independently.
if [[ $missing -ne 0 || $awk_status -ne 0 ]]; then
  if [[ $missing -ne 0 ]]; then
    echo "coverage-gate: FAILED: one or more packages are absent from the coverage profile (listed above)"
  fi
  exit 1
fi
echo "coverage-gate: every package meets its floor"
