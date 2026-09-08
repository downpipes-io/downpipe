#!/usr/bin/env bash
# Confirms the conformance vectors enumerated in the docs exactly equal the
# directory listing under internal/format/testdata/vectors/ (SPEC.md section 14).
#
# Three checks, all of which must hold:
#   1. The machine-readable corpus block in docs/format/CONFORMANCE.md (between the
#      BEGIN/END VECTOR CORPUS markers) equals the set of vector directories on disk,
#      with no documented vector missing on disk and no on-disk vector undocumented.
#   2. Every name in that corpus block is also enumerated, backticked, somewhere in
#      docs/format/SPEC.md, so the two documents never drift apart.
#   3. The on-disk listing is the set of immediate subdirectories of the vectors
#      directory (each a vector); nothing else lives there but the corpus README.md.
#
# This never edits a vector or a doc; it only reports drift and exits non-zero.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
spec_list="$(uncomment "$spec_md" | grep -oE '^- `[a-z0-9-]+`:' | sed 's/^- `//; s/`:$//' | LC_ALL=C sort)"

if [[ -z "$spec_list" ]]; then
  echo "::error::could not extract any enumerated vector from $spec_md; the '- \`name\`:' form has probably changed"
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
  exit 1
fi

echo "PASS: $count vectors; CONFORMANCE.md corpus block equals the directory listing and all are enumerated in SPEC.md."
