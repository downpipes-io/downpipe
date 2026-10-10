#!/usr/bin/env bash
# release-shape.sh: checks that a tag's GitHub release holds exactly the files a downpipe release carries,
# as ONE release for the tag, in the expected draft state.
#
# WHY IT EXISTS. release.yml uploads to the release from two places. GoReleaser opens a DRAFT release for
# the tag and uploads the six archives, their six SBOMs, checksums.txt and its cosign bundle. The SLSA
# provenance is signed in a separate reusable workflow, and that workflow's own upload step does not find a
# draft by its tag: given `upload-assets: true` it publishes a second release for the same tag holding only
# the provenance, and the tag then has one draft without the provenance and one published release without
# the binaries. So release.yml sets `upload-assets: false`, attaches the provenance to the GoReleaser draft
# by release id, reads the releases back, and runs this check over what the API returned.
#
# MODES
#   release-shape.sh expected --tag <tag> [--goreleaser <file>]
#       Prints the expected file names, one per line.
#   release-shape.sh draft-id --tag <tag> --releases <file> --write-id <file> [--goreleaser <file>]
#       Requires exactly one release for the tag, drafts included, and requires it to be a draft. Writes
#       its id to the --write-id file. This is the lookup release.yml uploads by.
#   release-shape.sh check --tag <tag> --releases <file> [--state draft|published] [--provenance <file>]
#                    [--goreleaser <file>]
#       Requires exactly one release for the tag, drafts included, in the given state (draft unless
#       --state says otherwise), holding exactly the expected files, each fully uploaded. With
#       --provenance, the release's provenance file must carry the sha256 digest of that local file.
#   release-shape.sh --self-test
#       Runs every mode over scripts/testdata/release-shape/split.json and variants of it. No network,
#       no token.
#
# --releases is the JSON array that GET /repos/{owner}/{repo}/releases returns, with every page merged into
# one array (`gh api --paginate 'repos/OWNER/REPO/releases?per_page=100' | jq -s 'add // []'`). A token
# with push access sees drafts in that list. A token without it does not, and a draft then reads as absent.
#
# THE EXPECTED NAMES COME FROM .goreleaser.yaml. project_name, the goos and goarch lists of its one build,
# and the formats and format_overrides of its one archive give the archives; each archive has a SBOM named
# after it; the checksum file has a signature named after it; and the provenance is
# <project_name>.intoto.jsonl, the provenance-name release.yml passes to the generator. The derivation reads
# the one-line `[a, b]` list form only, and it refuses (exit 2) any key that would change a name or add a
# release file it does not model, such as an archive name_template, a goamd64 level or a top-level nfpms
# block, rather than guess at the names.
#
# Exit status: 0 the shape holds, 1 it does not (every reason is printed), 2 the check could not run.

set -euo pipefail

# Sourcing this ARMS the completion guard: every route out of this script must declare a verdict or the
# guard forces a non-zero exit.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/verdict-guard.sh"

self="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# refuse ends the run at exit 2: the check could not run, which is neither a pass nor a shape finding.
refuse() {
  echo "::error::release-shape: $1" >&2
  verdict_skipped "$1" require
  exit 2
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# derive_names <goreleaser config> <version> prints the expected release file names, sorted, or prints
# one "REFUSE <reason>" line when the config holds a shape the derivation does not model.
derive_names() {
  awk -v version="$2" -v sq="'" '
    # trim drops surrounding blanks and quotes. The quote set is built from -v sq because this program is
    # itself single-quoted, and a dynamic regex is read the same way by gawk, mawk and the BSD awk.
    function trim(s) { gsub("^[ \t\"" sq "]+|[ \t\"" sq "]+$", "", s); return s }
    # flow turns a one-line "[a, b]" list into "a b", and returns "" for any other form.
    function flow(v,   inner, n, i, p, out, parts) {
      v = trim(v)
      if (v !~ /^\[.*\]$/) return ""
      inner = substr(v, 2, length(v) - 2)
      n = split(inner, parts, ",")
      out = ""
      for (i = 1; i <= n; i++) {
        p = trim(parts[i])
        if (p == "") return ""
        out = out (out == "" ? "" : " ") p
      }
      return out
    }
    function refuse(msg) { if (!refused) print "REFUSE " msg; refused = 1 }
    function value(line) { sub(/^[^:]*:[ \t]*/, "", line); return trim(line) }
    BEGIN {
      split("version project_name before builds archives checksum sboms signs release changelog", keys, " ")
      for (k in keys) allowed[keys[k]] = 1
    }
    /^[ \t]*#/ || /^[ \t]*$/ { next }
    {
      line = $0
      sub(/[ \t]+#.*$/, "", line)
    }
    line ~ /^[A-Za-z_]+:/ {
      section = line
      sub(/:.*$/, "", section)
      if (!(section in allowed)) refuse("top-level key \"" section "\" can add release files the derivation does not model")
      if (section == "project_name") project = value(line)
      next
    }
    section == "builds" {
      if (line ~ /^  - /) { builds++; if (builds > 1) refuse("more than one build"); sub(/^  - /, "    ", line) }
      if (line ~ /^    (targets|ignore|goarm|goarm64|goamd64|go386|gomips|goppc64|goriscv64|skip):/) {
        k = line; sub(/^ +/, "", k); sub(/:.*$/, "", k)
        refuse("builds." k " changes the platform set or the archive names")
      }
      if (line ~ /^    goos:/) { goos = flow(value(line)); if (goos == "") refuse("builds.goos is not a one-line [a, b] list") }
      if (line ~ /^    goarch:/) { goarch = flow(value(line)); if (goarch == "") refuse("builds.goarch is not a one-line [a, b] list") }
      next
    }
    section == "archives" {
      if (line ~ /^  - /) { archives++; if (archives > 1) refuse("more than one archive"); sub(/^  - /, "    ", line) }
      if (line ~ /^    (name_template|builds|ids|meta|format):/) {
        k = line; sub(/^ +/, "", k); sub(/:.*$/, "", k)
        refuse("archives." k " changes which archives exist or what they are called")
      }
      if (line ~ /^    formats:/) { formats = flow(value(line)); if (formats == "") refuse("archives.formats is not a one-line [a, b] list") }
      if (line ~ /^      - goos:/) { override_os = value(line); next }
      if (line ~ /^        formats:/) {
        f = flow(value(line))
        if (override_os == "" || f == "") refuse("archives.format_overrides is not in the \"- goos: x\" then \"formats: [y]\" form")
        override[override_os] = f
      }
      next
    }
    section == "checksum" {
      if (line ~ /^  name_template:/) checksum = value(line)
      if (line ~ /^  (disable|split|extra_files):/) refuse("checksum settings change the checksum files")
      next
    }
    section == "sboms" {
      if (line ~ /^  - /) { sboms++; if (sboms > 1) refuse("more than one sboms entry"); sub(/^  - /, "    ", line) }
      if (line ~ /^    artifacts:/ && value(line) != "archive") refuse("sboms.artifacts is not archive")
      if (line ~ /^      - /) {
        d = line; sub(/^      - /, "", d); d = trim(d)
        if (sbom_suffix != "" || d !~ /^[{][{] *[.]ArtifactName *[}][}]/) refuse("sboms.documents is not one \"{{ .ArtifactName }}<suffix>\" name")
        sub(/^[{][{] *[.]ArtifactName *[}][}]/, "", d)
        sbom_suffix = d
      }
      next
    }
    section == "signs" {
      if (line ~ /^  - /) { signs++; if (signs > 1) refuse("more than one signs entry"); sub(/^  - /, "    ", line) }
      if (line ~ /^    artifacts:/ && value(line) != "checksum") refuse("signs.artifacts is not checksum")
      if (line ~ /^    signature:/) {
        s = value(line)
        if (s !~ /^[$][{]artifact[}]/) refuse("signs.signature is not \"${artifact}<suffix>\"")
        sub(/^[$][{]artifact[}]/, "", s)
        sig_suffix = s
      }
      next
    }
    section == "release" {
      if (line ~ /^  (extra_files|disable|skip_upload|ids):/) refuse("release settings change which files the release holds")
      next
    }
    END {
      if (!refused) {
        if (project == "") refuse("no project_name")
        else if (goos == "" || goarch == "") refuse("no builds.goos or builds.goarch list")
        else if (formats == "") refuse("no archives.formats list")
        else if (checksum == "" || checksum ~ /[{][{]/) refuse("checksum.name_template is absent or templated")
        else if (sbom_suffix == "") refuse("no sboms.documents name")
        else if (sig_suffix == "") refuse("no signs.signature name")
      }
      if (refused) exit 0
      nos = split(goos, oses, " ")
      narch = split(goarch, arches, " ")
      for (i = 1; i <= nos; i++) {
        fl = (oses[i] in override) ? override[oses[i]] : formats
        nf = split(fl, fmts, " ")
        for (j = 1; j <= narch; j++) {
          for (m = 1; m <= nf; m++) {
            if (fmts[m] == "binary" || fmts[m] == "none") { refuse("archive format " fmts[m] " does not produce an archive"); exit 0 }
            name = project "_" version "_" oses[i] "_" arches[j] "." fmts[m]
            print name
            print name sbom_suffix
          }
        }
      }
      print checksum
      print checksum sig_suffix
      print project ".intoto.jsonl"
    }
  ' "$1" | LC_ALL=C sort
}

# expected_names <goreleaser config> <tag> fills $expected with the sorted names, or refuses.
expected_names() {
  local config="$1" tag="$2" version out
  [[ -f "$config" ]] || refuse "no GoReleaser config at $config"
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]] || refuse "tag \"$tag\" is not a vX.Y.Z release tag"
  version="${tag#v}"
  out="$(derive_names "$config" "$version")"
  if [[ "$out" == *"REFUSE "* ]]; then
    refuse "cannot derive the release file names from $config: $(printf '%s\n' "$out" | sed -n 's/^REFUSE //p' | head -1)"
  fi
  expected="$out"
  provenance_name="$(printf '%s\n' "$expected" | grep '\.intoto\.jsonl$')"
}

if [[ "${1:-}" == "--self-test" ]]; then
  fixture="$(mktemp -d)"
  verdict_guard_cleanup() { rm -rf "$fixture"; }
  split="$repo_root/scripts/testdata/release-shape/split.json"
  [[ -f "$split" ]] || refuse "the self-test fixture $split is missing"
  checked=0
  failed=0

  # expect runs one mode and checks its exit status and that its output carries every wanted fragment.
  expect() {
    local desc="$1" want_status="$2" status out frag
    shift 2
    local -a frags=()
    while [[ "$1" != "--" ]]; do frags+=("$1"); shift; done
    shift
    status=0
    out="$(bash "$self" "$@" 2>&1)" || status=$?
    checked=$((checked + 1))
    local ok=1
    [[ "$status" -eq "$want_status" ]] || ok=0
    for frag in ${frags[@]+"${frags[@]}"}; do [[ "$out" == *"$frag"* ]] || ok=0; done
    if [[ "$ok" -eq 1 ]]; then
      echo "ok   $desc"
    else
      echo "release-shape --self-test FAIL: $desc (wanted exit $want_status and: ${frags[*]}; got exit $status)" >&2
      printf '%s\n' "$out" | sed 's/^/    /' >&2
      failed=$((failed + 1))
    fi
  }

  # split.json is the split shape for v0.3.4, as the releases API returns it: the GoReleaser draft holding 14
  # files, and a second, published release for the same tag holding only the provenance. Ids, names, sizes
  # and digests are real API values; fields this check does not read are left out. Every other fixture is
  # derived from it here, so each one differs from a real API answer by the one property it is about.
  fixed="$fixture/fixed.json"
  jq '[(.[] | select(.draft)) as $d | (.[] | select(.draft | not)) as $s | $d | .assets += $s.assets]' "$split" > "$fixed"
  jq '.[0].assets |= map(select(.name != "downpipe_0.3.4_linux_arm64.tar.gz"))' "$fixed" > "$fixture/missing.json"
  jq '.[0].assets += [{"id": 1, "name": "notes.txt", "size": 5, "state": "uploaded", "digest": "sha256:00"}]' "$fixed" > "$fixture/extra.json"
  jq '.[0].draft = false' "$fixed" > "$fixture/published.json"
  jq '(.[0].assets[] | select(.name == "checksums.txt") | .state) = "starter"' "$fixed" > "$fixture/starter.json"
  jq '. + [{"id": 2, "tag_name": "v0.3.3", "name": "v0.3.3", "draft": false, "prerelease": false, "assets": []}]' "$fixed" > "$fixture/other-tag.json"
  printf '{"id": 1}\n' > "$fixture/not-array.json"
  printf 'provenance fixture\n' > "$fixture/local.intoto.jsonl"
  printf 'some other provenance\n' > "$fixture/other.intoto.jsonl"
  jq --arg d "sha256:$(sha256_of "$fixture/local.intoto.jsonl")" \
    '(.[0].assets[] | select(.name == "downpipe.intoto.jsonl") | .digest) = $d' "$fixed" > "$fixture/digest.json"
  awk '{ print } $0 == "    formats: [tar.gz]" { print "    name_template: \"{{ .ProjectName }}-{{ .Version }}\"" }' "$repo_root/.goreleaser.yaml" > "$fixture/name-template.yaml"
  grep -q 'name_template: "{{ .ProjectName }}' "$fixture/name-template.yaml" || refuse "the name_template fixture was not written; .goreleaser.yaml's archives.formats line has moved"

  # The derivation, against the real release: the names it gives for v0.3.4 from this repository's
  # .goreleaser.yaml must be the 15 names the two v0.3.4 releases hold between them.
  status=0
  derived="$(bash "$self" expected --tag v0.3.4 2>&1 | grep -v '^VERDICT')" || status=$?
  real="$(jq -r '[.[].assets[].name] | sort | .[]' "$split" | LC_ALL=C sort)"
  checked=$((checked + 1))
  if [[ "$status" -eq 0 && "$derived" == "$real" && "$(printf '%s\n' "$derived" | grep -c .)" -eq 15 ]]; then
    echo "ok   the names derived from .goreleaser.yaml for v0.3.4 are the 15 files of the real v0.3.4 release"
  else
    echo "release-shape --self-test FAIL: the derived names for v0.3.4 differ from the real release (exit $status)" >&2
    diff <(printf '%s\n' "$real") <(printf '%s\n' "$derived") >&2 || true
    failed=$((failed + 1))
  fi

  expect "the split shape fails, naming the second release and what each one lacks" 1 \
    "2 releases for tag v0.3.4" "release 403509659 (draft) for v0.3.4 is missing 1 expected file(s): downpipe.intoto.jsonl" \
    "release 403510166 for v0.3.4 is published; a draft is expected" -- check --tag v0.3.4 --releases "$split"
  expect "the split shape gives no draft id to upload to" 1 "2 releases for tag v0.3.4" -- \
    draft-id --tag v0.3.4 --releases "$split" --write-id "$fixture/split-id"
  expect "one draft holding the 15 files passes" 0 "PASS: release 403509659 (draft) holds exactly the 15 expected files for v0.3.4" -- \
    check --tag v0.3.4 --releases "$fixed"
  expect "one draft for the tag gives its id" 0 "draft release 403509659" -- \
    draft-id --tag v0.3.4 --releases "$fixed" --write-id "$fixture/fixed-id"
  checked=$((checked + 1))
  if [[ "$(cat "$fixture/fixed-id" 2>/dev/null)" == "403509659" ]]; then
    echo "ok   the id file holds the draft's id and nothing else"
  else
    echo "release-shape --self-test FAIL: the id file does not hold exactly 403509659" >&2
    failed=$((failed + 1))
  fi
  expect "a missing archive fails and names it" 1 "is missing 1 expected file(s): downpipe_0.3.4_linux_arm64.tar.gz" -- \
    check --tag v0.3.4 --releases "$fixture/missing.json"
  expect "an extra file fails and names it" 1 "holds 1 unexpected file(s): notes.txt" -- \
    check --tag v0.3.4 --releases "$fixture/extra.json"
  expect "a published release fails where a draft is expected" 1 "is published; a draft is expected" -- \
    check --tag v0.3.4 --releases "$fixture/published.json"
  expect "a published release gives no draft id" 1 "is published; a draft is expected" -- \
    draft-id --tag v0.3.4 --releases "$fixture/published.json" --write-id "$fixture/published-id"
  expect "the same published release passes when --state published is asked for" 0 "PASS" -- \
    check --tag v0.3.4 --releases "$fixture/published.json" --state published
  expect "a tag with no release fails" 1 "no release for tag v0.3.5" -- \
    check --tag v0.3.5 --releases "$fixed"
  expect "a release for another tag is not counted against this one" 0 "PASS" -- \
    check --tag v0.3.4 --releases "$fixture/other-tag.json"
  expect "a file that is not fully uploaded fails" 1 "not fully uploaded: checksums.txt (starter)" -- \
    check --tag v0.3.4 --releases "$fixture/starter.json"
  expect "a provenance digest equal to the local file's passes" 0 "PASS" "digest matches" -- \
    check --tag v0.3.4 --releases "$fixture/digest.json" --provenance "$fixture/local.intoto.jsonl"
  expect "a provenance digest that differs from the local file's fails" 1 "downpipe.intoto.jsonl digest" "differs from the local file" -- \
    check --tag v0.3.4 --releases "$fixture/digest.json" --provenance "$fixture/other.intoto.jsonl"
  expect "an archive name_template is refused rather than guessed at" 2 "archives.name_template" -- \
    check --tag v0.3.4 --releases "$fixed" --goreleaser "$fixture/name-template.yaml"
  expect "a releases file that is not a JSON array is refused" 2 "is not a JSON array" -- \
    check --tag v0.3.4 --releases "$fixture/not-array.json"

  echo "release-shape --self-test: $((checked - failed)) of $checked assertion(s) passed"
  verdict_reached "$failed" "$checked"
  exit "$((failed > 0 ? 1 : 0))"
fi

mode="${1:-}"
[[ "$mode" == "expected" || "$mode" == "draft-id" || "$mode" == "check" ]] || refuse "usage: release-shape.sh expected|draft-id|check --tag <tag> ... (or --self-test)"
shift
tag=""
releases=""
state="draft"
provenance=""
write_id=""
config="$repo_root/.goreleaser.yaml"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) tag="${2:-}"; shift 2 ;;
    --releases) releases="${2:-}"; shift 2 ;;
    --state) state="${2:-}"; shift 2 ;;
    --provenance) provenance="${2:-}"; shift 2 ;;
    --write-id) write_id="${2:-}"; shift 2 ;;
    --goreleaser) config="${2:-}"; shift 2 ;;
    *) refuse "unrecognised argument \"$1\"" ;;
  esac
done
[[ -n "$tag" ]] || refuse "--tag is required"
[[ "$state" == "draft" || "$state" == "published" ]] || refuse "--state is draft or published, not \"$state\""

expected=""
provenance_name=""
expected_names "$config" "$tag"
expected_count="$(printf '%s\n' "$expected" | grep -c .)"

if [[ "$mode" == "expected" ]]; then
  printf '%s\n' "$expected"
  verdict_reached 0 "$expected_count"
  exit 0
fi

[[ -n "$releases" && -f "$releases" ]] || refuse "--releases must name a file of release JSON"
jq -e 'type == "array"' "$releases" >/dev/null 2>&1 || refuse "$releases is not a JSON array of releases"
if [[ "$mode" == "draft-id" && -z "$write_id" ]]; then refuse "draft-id needs --write-id <file>"; fi
if [[ -n "$provenance" && ! -f "$provenance" ]]; then refuse "--provenance names no file: $provenance"; fi

failures=0
checks=0
finding() {
  echo "::error::release-shape: $1"
  failures=$((failures + 1))
}

total="$(jq 'length' "$releases")"
ids="$(jq -r --arg t "$tag" '.[] | select(.tag_name == $t) | .id' "$releases")"
count="$(printf '%s' "$ids" | grep -c . || true)"
checks=$((checks + 1))
if [[ "$count" -eq 0 ]]; then
  finding "no release for tag $tag among the $total release(s) read, drafts included"
elif [[ "$count" -gt 1 ]]; then
  summary="$(jq -r --arg t "$tag" '[.[] | select(.tag_name == $t) | "id \(.id) \(if .draft then "draft" else "published" end) holding \(.assets | length) file(s)"] | join("; ")' "$releases")"
  finding "$count releases for tag $tag, and exactly one is expected, drafts included: $summary"
fi

for id in $ids; do
  rel="$(jq -c --argjson id "$id" '.[] | select(.id == $id)' "$releases")"
  is_draft="$(jq -r '.draft == true' <<<"$rel")"
  label="draft"
  [[ "$is_draft" == "true" ]] || label="published"
  checks=$((checks + 1))
  if [[ "$state" == "draft" && "$is_draft" != "true" ]]; then
    finding "release $id for $tag is published; a draft is expected"
  elif [[ "$state" == "published" && "$is_draft" == "true" ]]; then
    finding "release $id for $tag is a draft; a published release is expected"
  fi
  [[ "$mode" == "check" ]] || continue

  actual="$(jq -r '.assets[].name' <<<"$rel" | LC_ALL=C sort)"
  missing="$(LC_ALL=C comm -23 <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") | grep . || true)"
  extra="$(LC_ALL=C comm -13 <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") | grep . || true)"
  dupes="$(printf '%s\n' "$actual" | uniq -d | grep . || true)"
  checks=$((checks + expected_count))
  if [[ -n "$missing" ]]; then
    finding "release $id ($label) for $tag is missing $(printf '%s\n' "$missing" | grep -c .) expected file(s): $(printf '%s\n' "$missing" | paste -sd ' ' -)"
  fi
  if [[ -n "$extra" ]]; then
    finding "release $id ($label) for $tag holds $(printf '%s\n' "$extra" | grep -c .) unexpected file(s): $(printf '%s\n' "$extra" | paste -sd ' ' -)"
  fi
  if [[ -n "$dupes" ]]; then
    finding "release $id ($label) for $tag holds more than one file named: $(printf '%s\n' "$dupes" | paste -sd ' ' -)"
  fi

  checks=$((checks + 1))
  partial="$(jq -r '[.assets[] | select(.state != "uploaded") | "\(.name) (\(.state))"] | join(", ")' <<<"$rel")"
  if [[ -n "$partial" ]]; then
    finding "release $id ($label) for $tag has file(s) not fully uploaded: $partial"
  fi

  if [[ -n "$provenance" ]]; then
    checks=$((checks + 1))
    want="sha256:$(sha256_of "$provenance")"
    got="$(jq -r --arg n "$provenance_name" '[.assets[] | select(.name == $n) | (.digest // "none")] | first // ""' <<<"$rel")"
    if [[ -z "$got" ]]; then
      finding "release $id ($label) for $tag holds no $provenance_name, so its digest cannot be compared"
    elif [[ "$got" != "$want" ]]; then
      finding "release $id ($label) for $tag: $provenance_name digest $got differs from the local file's $want"
    else
      echo "release-shape: release $id $provenance_name digest matches the local file ($want)"
    fi
  fi
done

if [[ "$failures" -gt 0 ]]; then
  echo "release-shape: FAIL for $tag: $failures finding(s) over $checks check(s)"
  verdict_reached "$failures" "$checks"
  exit 1
fi

if [[ "$mode" == "draft-id" ]]; then
  printf '%s\n' "$ids" > "$write_id"
  echo "release-shape: tag $tag has one release, draft release $ids"
else
  echo "release-shape: PASS: release $ids ($state) holds exactly the $expected_count expected files for $tag"
fi
verdict_reached 0 "$checks"
