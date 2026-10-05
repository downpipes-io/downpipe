#!/usr/bin/env bash
# Confirms the conformance vectors enumerated in the docs exactly equal the
# directory listing under internal/format/testdata/vectors/ (SPEC.md section 14).
#
# Three checks, all of which must hold:
#   1. The machine-readable corpus block in docs/format/CONFORMANCE.md (between the
#      BEGIN/END VECTOR CORPUS markers) equals the set of vector directories on disk,
#      with no documented vector missing on disk and no on-disk vector undocumented.
#   2. The same names, and no others, are enumerated as list items in SPEC.md section 14
#      (Conformance vectors), so the two documents never drift apart.
#   3. The on-disk listing is the set of immediate subdirectories of the vectors
#      directory (each a vector); nothing else lives there but the corpus README.md.
#
# This never edits a vector or a doc; it only reports drift and exits non-zero.
#
# --self-test runs the gate over a small fixture tree and asserts it passes a SPEC.md whose other
# sections carry the same "- `name`:" list form, and fails a section 14 that misses or adds a vector.

set -euo pipefail

# Sourcing this ARMS the completion guard: every route out of this script must declare a verdict or the
# guard forces a non-zero exit.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/verdict-guard.sh"

if [[ "${1:-}" == "--self-test" ]]; then
  self="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
  fixture="$(mktemp -d)"
  verdict_guard_cleanup() { rm -rf "$fixture"; }
  checked=0
  failed=0

  # build writes a fixture repository: two vectors on disk and in the corpus block, a SPEC.md whose
  # section 12 has a descriptor list in the vector list form, and a section 14 with the given list
  # (printed with %b, so its \n escapes become line breaks).
  build() {
    local root="$1" section14="$2"
    mkdir -p "$root/internal/format/testdata/vectors/alpha" "$root/internal/format/testdata/vectors/beta" "$root/docs/format"
    printf '# corpus\n' > "$root/internal/format/testdata/vectors/README.md"
    printf '<!-- BEGIN VECTOR CORPUS -->\n```\nalpha\nbeta\n```\n<!-- END VECTOR CORPUS -->\n' > "$root/docs/format/CONFORMANCE.md"
    printf '# Spec\n\n## 12. Source types\n\n### 12.3 Secret descriptors\n\n- `store`: the store id.\n- `comment`: the comment.\n\n## 14. Conformance vectors\n\n### 14.2 Positive vectors\n\n%b\n## 15. Compatibility\n\n- `wiring`: not a vector.\n' "$section14" > "$root/docs/format/SPEC.md"
  }

  # expect runs the gate over one fixture and checks its exit status and one line of its output.
  expect() {
    local desc="$1" section14="$2" want_status="$3" want_text="$4" root out status
    root="$fixture/$checked"
    build "$root" "$section14"
    status=0
    out="$(VECTORS_LISTING_ROOT="$root" bash "$self" 2>&1)" || status=$?
    checked=$((checked + 1))
    if [[ "$status" -ne "$want_status" || "$out" != *"$want_text"* ]]; then
      echo "check-vectors-listing --self-test FAIL: $desc (wanted exit $want_status and \"$want_text\", got exit $status)" >&2
      printf '%s\n' "$out" >&2
      failed=$((failed + 1))
    else
      echo "ok   $desc"
    fi
  }

  expect "a descriptor list outside section 14 is not read as vectors" \
    '- `alpha`: first.\n- `beta`: second.\n' 0 "PASS: 2 vectors"
  expect "a vector missing from section 14 fails" \
    '- `alpha`: first.\n' 1 "not enumerated in SPEC.md"
  expect "an extra name in section 14 fails" \
    '- `alpha`: first.\n- `beta`: second.\n- `gamma`: third.\n' 1 "  - gamma"

  echo "check-vectors-listing --self-test: $((checked - failed)) of $checked assertion(s) passed"
  verdict_reached "$failed" "$checked"
  exit "$((failed > 0 ? 1 : 0))"
fi

# VECTORS_LISTING_ROOT is for --self-test only, which points the gate at a fixture tree.
repo_root="${VECTORS_LISTING_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
vectors_dir="$repo_root/internal/format/testdata/vectors"
conformance_md="$repo_root/docs/format/CONFORMANCE.md"
spec_md="$repo_root/docs/format/SPEC.md"

fail=0

# 1. On-disk listing: immediate subdirectories of the vectors directory.
disk_list="$(find "$vectors_dir" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | LC_ALL=C sort)"

# uncomment blanks out every HTML comment span, so a line parked inside <!-- --> is not read as
# live text. It preserves line numbering by printing one line per input line.
#
# A LINE-ORIENTED PATTERN CANNOT SEE A BLOCK COMMENT AROUND IT. Parking a withdrawn entry verbatim
# in an HTML comment, which is how a Markdown author actually retires a list item, put a vector back
# into the derived set while the normative document enumerated it nowhere a reader would see. That is
# the same failure the command-set pin had before it was parsed, and it was proven here after this
# script's set-equality check was already in place.
uncomment() {
  awk '
    {
      line = $0; out = ""
      while (1) {
        if (incmt) {
          i = index(line, "-->")
          if (i == 0) { line = ""; break }
          line = substr(line, i + 3); incmt = 0
        } else {
          i = index(line, "<!--")
          if (i == 0) { out = out line; break }
          out = out substr(line, 1, i - 1); line = substr(line, i + 4); incmt = 1
        }
      }
      print out
    }
  ' "$1"
}

# 2. Documented listing: the fenced block between the corpus markers in CONFORMANCE.md.
#
# The markers are themselves HTML comments, so the block cannot simply be uncommented first. Comment
# spans are tracked only INSIDE the block, where a name parked on its own line between <!-- and -->
# would otherwise match the bare-name form and be counted as documented.
doc_list="$(awk '
  /BEGIN VECTOR CORPUS/ {grab=1; incmt=0; next}
  /END VECTOR CORPUS/   {grab=0}
  !grab {next}
  incmt { if (index($0, "-->") > 0) incmt=0; next }
  index($0, "<!--") > 0 { if (index($0, "-->") == 0) incmt=1; next }
  /^[a-z0-9-]+$/ {print}
' "$conformance_md" | LC_ALL=C sort)"

if [[ -z "$doc_list" ]]; then
  echo "::error::could not extract the VECTOR CORPUS block from $conformance_md"
  # The documented corpus is one side of every comparison below, so with none extracted nothing was
  # compared. A mandatory skip, not a counted failure.
  verdict_skipped "could not extract the VECTOR CORPUS block from $conformance_md, so no name was compared" require
  exit 1
fi

# 3. Set-equality between the documented corpus and the on-disk listing.
only_in_docs="$(comm -23 <(printf '%s\n' "$doc_list") <(printf '%s\n' "$disk_list"))"
only_on_disk="$(comm -13 <(printf '%s\n' "$doc_list") <(printf '%s\n' "$disk_list"))"

if [[ -n "$only_in_docs" ]]; then
  echo "::error::vectors enumerated in CONFORMANCE.md but MISSING on disk:"
  printf '  - %s\n' $only_in_docs
  fail=1
fi
if [[ -n "$only_on_disk" ]]; then
  echo "::error::vector directories on disk but UNDOCUMENTED in the CONFORMANCE.md corpus block:"
  printf '  - %s\n' $only_on_disk
  fail=1
fi

# 4. SPEC.md's own enumeration must be the SAME SET, in both directions.
#
# This used to ask only whether each corpus name appeared backticked SOMEWHERE in SPEC.md, and that
# was blind twice over. A name mentioned in passing satisfied it without being enumerated at all, and
# nothing ever looked the other way: retiring gzip-codec from disk and from the corpus block left
# SPEC.md still enumerating it and this script still printing PASS, while SPEC.md is the NORMATIVE
# document and an implementer reading it would go looking for a vector that is not in the corpus.
#
# The names are taken from SPEC.md's list items rather than from any backtick, so a re-mention in
# section 14.4's prose neither satisfies nor breaks the check.
#
# ONLY SECTION 14 IS READ. The list form is not unique to the vector enumeration: section 12.3 lists
# the secret descriptor members as "- `store`:", "- `comment`:" and so on, and when it did, this read
# five member names as vectors and failed main. The section runs from its "## 14." heading to the
# next "## " heading.
spec_list="$(uncomment "$spec_md" | awk '/^## /{in14 = ($0 ~ /^## 14\./)} in14' | grep -oE '^- `[a-z0-9-]+`:' | sed 's/^- `//; s/`:$//' | LC_ALL=C sort || true)"

if [[ -z "$spec_list" ]]; then
  echo "::error::could not extract any enumerated vector from section 14 of $spec_md; the '## 14.' heading or the '- \`name\`:' form has probably changed"
  verdict_skipped "could not extract any enumerated vector from section 14 of $spec_md, so the SPEC.md half compared nothing" require
  exit 1
fi

missing_in_spec="$(comm -23 <(printf '%s\n' "$doc_list") <(printf '%s\n' "$spec_list"))"
only_in_spec="$(comm -13 <(printf '%s\n' "$doc_list") <(printf '%s\n' "$spec_list"))"

if [[ -n "$missing_in_spec" ]]; then
  echo "::error::vectors in the corpus block not enumerated in SPEC.md:"
  printf '  - %s\n' $missing_in_spec
  fail=1
fi
if [[ -n "$only_in_spec" ]]; then
  echo "::error::vectors enumerated in SPEC.md that are not in the CONFORMANCE.md corpus block:"
  printf '  - %s\n' $only_in_spec
  fail=1
fi

# 5. Nothing but the corpus README.md lives beside the vector directories, which the header has always
# claimed and nothing has ever checked. A stray file here is either a vector that did not get its own
# directory or a leftover, and both are worth seeing.
stray="$(find "$vectors_dir" -mindepth 1 -maxdepth 1 ! -type d ! -name README.md -exec basename {} \;)"
if [[ -n "$stray" ]]; then
  echo "::error::unexpected files beside the vector directories:"
  printf '  - %s\n' $stray
  fail=1
fi

# The count is the number of vector directories actually found on disk, which is the population every
# set-equality comparison above was made over, not the number of comparisons this file wanted to make.
count="$(printf '%s\n' "$disk_list" | grep -c . || true)"

if [[ "$fail" -ne 0 ]]; then
  echo "FAIL: the enumerated vector names do not exactly equal the directory listing."
  verdict_reached "$fail" "$count"
  exit 1
fi

echo "PASS: $count vectors; CONFORMANCE.md corpus block equals the directory listing and all are enumerated in SPEC.md."
verdict_reached 0 "$count"
