#!/usr/bin/env bash
# Confirms the committed vendor/ tree, which holds the ML-DSA-87 verification code, is byte for byte what
# the pinned upstream modules produce.
#
# WHY THIS EXISTS. Go builds and tests this module from vendor/ (a vendor/ directory is the default build
# source), so go.sum is not consulted for those packages. Nothing else compares the contents of vendor/ with
# the upstream release. A one-line edit to the vendored signature code would change what the reader accepts
# as a good archive, and the diff would be the only thing that showed it. This gate removes that gap.
#
# WHAT IT CHECKS. All of these must hold.
#   1. go.mod requires each pinned module at its exact pinned version.
#   2. go.sum holds the pinned h1 checksum for each pinned module and for its go.mod file.
#   3. vendor/modules.txt names each pinned module at its pinned version.
#   4. Re-deriving the vendor tree from the pinned modules (go mod vendor into a scratch directory, with a
#      fresh module cache) gives a tree with no byte difference from the committed vendor/ tree: no changed
#      file, no extra file, no missing file.
#   5. Re-deriving changed neither go.mod nor go.sum.
#
# NETWORK. Step 4 downloads only the pinned modules, through the Go module proxy, with the checksum
# database on (GOSUMDB=sum.golang.org) and GONOSUMDB, GONOSUMCHECK, GOPRIVATE and GOINSECURE unset. Go also
# checks each download against go.sum. No other network is used.
#
# TO BUMP A PINNED MODULE: change go.mod, run `go mod tidy && go mod vendor`, then change the pins below to
# the new version and the h1 values go.sum now holds, in the same commit.
#
# USAGE
#   bash scripts/check-vendor-integrity.sh              check the repository this script lives in
#   bash scripts/check-vendor-integrity.sh --self-test  prove the check fails on a changed, added or removed
#                                                  vendored file and on a changed pin, and passes when
#                                                  each is put back

set -euo pipefail

# Sourcing this ARMS the completion guard: every route out of this script must declare a verdict or the
# guard forces a non-zero exit.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/verdict-guard.sh"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Pinned upstream modules: path, exact version, h1 checksum of the module zip, h1 checksum of its go.mod.
pins=(
  "filippo.io/mldsa v1.0.0 h1:DSyjDhIEKrGEO/RZfI60iuXI83Yzy8jDcbqMuPySK5U= h1:32qQ5yj3R24Eu03iWFWchdC3OB653wPvoepWejkefbY="
  "golang.org/x/crypto v0.57.0 h1:3ZVCjf8Ggz7zneR/EHRVx68Ctf+2pmIMP2UFhh9cC6M= h1:Fdz0i5U6CoizGwLda9DttjSk6qlZo25zYNtR+ycvuZA="
)

work=""
verdict_guard_cleanup() {
  if [[ -n "$work" && -d "$work" ]]; then
    # The module cache may be read-only (a Go that ignores -modcacherw), so make it writable first. A
    # cleanup problem is not a finding about vendor/, so it stays out of the verdict.
    chmod -R u+w "$work" 2>/dev/null || true
    rm -rf "$work" 2>/dev/null || true
  fi
}

failures=0
checks=0

fail() {
  echo "::error::$*" >&2
  failures=$((failures + 1))
}

# check_pins <go.mod> <go.sum> <modules.txt>: checks 1 to 3.
check_pins() {
  local gomod="$1" gosum="$2" modules="$3" pin path ver h1 h1mod
  for pin in "${pins[@]}"; do
    read -r path ver h1 h1mod <<<"$pin"
    checks=$((checks + 1))
    if ! grep -qE "^(require[[:space:]]+)?[[:space:]]*${path//./\\.}[[:space:]]+${ver//./\\.}([[:space:]]|$)" "$gomod"; then
      fail "go.mod does not require $path at the pinned $ver"
    fi
    checks=$((checks + 1))
    if ! grep -qxF "$path $ver $h1" "$gosum"; then
      fail "go.sum does not hold the pinned checksum $h1 for $path $ver"
    fi
    checks=$((checks + 1))
    if ! grep -qxF "$path $ver/go.mod $h1mod" "$gosum"; then
      fail "go.sum does not hold the pinned go.mod checksum $h1mod for $path $ver"
    fi
    checks=$((checks + 1))
    if ! grep -qxF "# $path $ver" "$modules"; then
      fail "vendor/modules.txt does not name $path at the pinned $ver"
    fi
  done
  # Allowlist: every module vendor/modules.txt lists must be one of the pins. A module added to go.mod,
  # go.sum and vendor/ together is re-derived identically, so only this check can refuse it.
  local listed known
  while IFS= read -r listed; do
    [[ -z "$listed" ]] && continue
    known=0
    for pin in "${pins[@]}"; do
      read -r path ver _ <<<"$pin"
      [[ "$listed" == "$path $ver" ]] && known=1
    done
    checks=$((checks + 1))
    if [[ $known -eq 0 ]]; then
      fail "vendor/modules.txt lists \"$listed\", which is not in the pinned module list of scripts/check-vendor-integrity.sh"
    fi
  done < <(sed -n 's/^# \([^[:space:]]*[[:space:]][^[:space:]]*\).*$/\1/p' "$modules")
}

# sums_unchanged <go.mod> <go.sum> <cksum-of-go.mod> <cksum-of-go.sum>: check 5.
sums_unchanged() {
  [[ "$(cksum <"$1")" == "$3" && "$(cksum <"$2")" == "$4" ]]
}

# derive <out-dir>: re-derive the vendor tree from the pinned modules into <out-dir>.
derive() {
  local out="$1"
  (
    cd "$repo_root"
    unset GONOSUMDB GONOSUMCHECK GOPRIVATE GOINSECURE GONOPROXY GOVCS
    # Ignore the user's go env -w file and any go.work, so neither can change what is fetched or checked.
    export GOENV=off
    export GOWORK=off
    export GOFLAGS="-mod=mod -modcacherw"
    export GOPROXY="https://proxy.golang.org"
    export GOSUMDB="sum.golang.org"
    export GOMODCACHE="$work/modcache"
    export GOPATH="$work/gopath"
    go mod vendor -o "$out"
  )
}

# compare_trees <committed-vendor> <derived-vendor>: check 4. Prints the differing names.
compare_trees() {
  local committed="$1" derived="$2" out
  checks=$((checks + 1))
  if ! out="$(diff -r -q "$committed" "$derived" 2>&1)"; then
    fail "vendor/ differs from the tree re-derived from the pinned modules:"
    printf '%s\n' "$out" >&2
    return 1
  fi
  return 0
}

# check_repo: checks 1 to 5 against the repository. Leaves the derived tree in $work/derived.
check_repo() {
  local before_mod before_sum
  check_pins "$repo_root/go.mod" "$repo_root/go.sum" "$repo_root/vendor/modules.txt"
  before_mod="$(cksum <"$repo_root/go.mod")"
  before_sum="$(cksum <"$repo_root/go.sum")"
  checks=$((checks + 1))
  if ! derive "$work/derived"; then
    fail "go mod vendor failed, so vendor/ could not be re-derived from the pinned modules"
    return 0
  fi
  compare_trees "$repo_root/vendor" "$work/derived" || true
  checks=$((checks + 1))
  if ! sums_unchanged "$repo_root/go.mod" "$repo_root/go.sum" "$before_mod" "$before_sum"; then
    fail "re-deriving changed go.mod or go.sum"
  fi
}

work="$(mktemp -d "${TMPDIR:-/tmp}/vendor-integrity.XXXXXX")"
mkdir -p "$work/modcache" "$work/gopath"

if [[ "${1:-}" != "--self-test" ]]; then
  check_repo
  if [[ $failures -ne 0 ]]; then
    echo "vendor integrity: FAIL ($failures finding(s))" >&2
    verdict_reached "$failures" "$checks"
    exit 1
  fi
  echo "vendor integrity: vendor/ matches the pinned modules byte for byte ($checks checks)."
  verdict_reached 0 "$checks"
  exit 0
fi

# ---- self-test ----
# Derive once, then grade the comparison and the pin check over copies. Each case must fail when the
# tree is changed and pass when it is put back. A case that does not fail when changed, or does not pass
# when restored, is a finding.
if ! derive "$work/derived"; then
  echo "::error::self-test could not re-derive the vendor tree" >&2
  verdict_reached 1 1
  exit 1
fi

cp -R "$repo_root/vendor" "$work/copy"
target="$work/copy/filippo.io/mldsa/mldsa.go"
if [[ ! -f "$target" ]]; then
  echo "::error::self-test target $target does not exist" >&2
  verdict_reached 1 1
  exit 1
fi

st_fail=0
st_checks=0
expect() { # expect <pass|fail> <label> <command...>
  local want="$1" label="$2" rc=0
  shift 2
  "$@" >/dev/null 2>&1 || rc=$?
  st_checks=$((st_checks + 1))
  if [[ "$want" == "pass" && $rc -ne 0 ]] || [[ "$want" == "fail" && $rc -eq 0 ]]; then
    echo "self-test FAIL: $label (wanted $want, exit $rc)" >&2
    st_fail=$((st_fail + 1))
  else
    echo "self-test ok: $label (exit $rc)"
  fi
}

cmp_quiet() { diff -r -q "$1" "$2"; }

expect pass "untouched copy matches the derived tree" cmp_quiet "$work/copy" "$work/derived"

# Case 1: one byte changed in place.
cp "$target" "$work/orig.go"
printf 'x' | dd of="$target" bs=1 seek=0 count=1 conv=notrunc 2>/dev/null
expect fail "one changed byte in mldsa.go is refused" cmp_quiet "$work/copy" "$work/derived"
cp "$work/orig.go" "$target"
expect pass "restored mldsa.go is accepted" cmp_quiet "$work/copy" "$work/derived"

# Case 2: one byte appended.
printf 'x' >>"$target"
expect fail "one appended byte in mldsa.go is refused" cmp_quiet "$work/copy" "$work/derived"
cp "$work/orig.go" "$target"
expect pass "restored mldsa.go is accepted again" cmp_quiet "$work/copy" "$work/derived"

# Case 3: an extra file.
printf 'package mldsa\n' >"$work/copy/filippo.io/mldsa/extra.go"
expect fail "an added file is refused" cmp_quiet "$work/copy" "$work/derived"
rm -f "$work/copy/filippo.io/mldsa/extra.go"
expect pass "the extra file removed is accepted" cmp_quiet "$work/copy" "$work/derived"

# Case 4: a missing file.
mv "$target" "$work/mldsa.go.held"
expect fail "a removed file is refused" cmp_quiet "$work/copy" "$work/derived"
mv "$work/mldsa.go.held" "$target"
expect pass "the file put back is accepted" cmp_quiet "$work/copy" "$work/derived"

# Case 5: the pin check against a changed go.sum.
cp "$repo_root/go.sum" "$work/go.sum.copy"
pins_only() { # runs check_pins in a subshell so its counters do not leak
  (check_pins "$repo_root/go.mod" "$1" "$repo_root/vendor/modules.txt" && [[ $failures -eq 0 ]]) 2>/dev/null
}
expect pass "go.sum as committed matches the pins" pins_only "$work/go.sum.copy"
sed 's/^filippo.io\/mldsa v1.0.0 h1:D/filippo.io\/mldsa v1.0.0 h1:E/' "$repo_root/go.sum" >"$work/go.sum.copy"
expect fail "a changed go.sum checksum is refused" pins_only "$work/go.sum.copy"

# Case 6: a module in vendor/modules.txt that is not in the pinned list.
cp "$repo_root/vendor/modules.txt" "$work/modules.copy"
pins_with_modules() { (check_pins "$repo_root/go.mod" "$repo_root/go.sum" "$1" && [[ $failures -eq 0 ]]) 2>/dev/null; }
expect pass "modules.txt as committed lists only pinned modules" pins_with_modules "$work/modules.copy"
printf '# example.com/extra v1.0.0\nexample.com/extra\n' >>"$work/modules.copy"
expect fail "an unpinned module in modules.txt is refused" pins_with_modules "$work/modules.copy"

# Case 7: a go.mod or go.sum changed during re-derive.
sum_mod="$(cksum <"$repo_root/go.mod")"
sum_sum="$(cksum <"$repo_root/go.sum")"
cp "$repo_root/go.sum" "$work/go.sum.planted"
expect pass "go.sum unchanged is accepted" sums_unchanged "$repo_root/go.mod" "$work/go.sum.planted" "$sum_mod" "$sum_sum"
printf 'x' >>"$work/go.sum.planted"
expect fail "a changed go.sum is refused" sums_unchanged "$repo_root/go.mod" "$work/go.sum.planted" "$sum_mod" "$sum_sum"
cp "$repo_root/go.mod" "$work/go.mod.planted"
printf 'x' >>"$work/go.mod.planted"
expect fail "a changed go.mod is refused" sums_unchanged "$work/go.mod.planted" "$repo_root/go.sum" "$sum_mod" "$sum_sum"

# Case 8: a bad go.work and a bad go env file must not change the re-derive.
printf 'this is not a go.work file\n' >"$work/bad.work"
printf 'this is not a go env file\n' >"$work/bad.env"
rederive_with_bad_env() {
  GOWORK="$work/bad.work" GOENV="$work/bad.env" derive "$work/derived-env" && cmp_quiet "$work/copy" "$work/derived-env"
}
expect pass "a bad GOWORK and GOENV leave the re-derive unchanged" rederive_with_bad_env

if [[ $st_fail -ne 0 ]]; then
  echo "vendor integrity self-test: FAIL ($st_fail of $st_checks)" >&2
  verdict_reached "$st_fail" "$st_checks"
  exit 1
fi
echo "vendor integrity self-test: $st_checks cases, every change refused and every restore accepted."
verdict_reached 0 "$st_checks"
