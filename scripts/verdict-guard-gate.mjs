#!/usr/bin/env node
// verdict-guard-gate: every script entry point this repository actually runs must be enrolled in a
// shared completion guard.
//
// WHY THIS GATE EXISTS. A guard closes the class where an entry point reaches exit 0 without ever
// reaching its own verdict, so nothing in the run was capable of failing. A guard that only some entry
// points opt into is the same defect wearing a helmet, so the requirement is not a list kept by hand in
// this file: it is DERIVED from what the repository actually runs.
//
// WHY THIS REPOSITORY'S GATE IS NOT A COPY OF THE OTHER TWO. website and control-plane derive their
// entry points from package.json. This repository is a Go repository with NO package.json at the root,
// and its gates are bash scripts driven by make targets, so that derivation would have found nothing at
// all here and passed. The channel is the Makefile instead, and the enrolment probe understands two
// guard modules rather than one:
//
//   scripts/lib/verdict-guard.mjs  arms node entry points, shared verbatim with website and control-plane
//   scripts/lib/verdict-guard.sh   arms bash entry points, written here because the node guard cannot
//
// WHAT THIS GATE DELIBERATELY DOES NOT REQUIRE, and it is most of the repository's checking. `go test`,
// `go vet`, `go build`, `gofmt`, `golangci-lint` and `gremlins` are frameworks that report their own
// verdict: the Go test runner prints ok/FAIL per package and exits on its own tally, so there is no
// point at which this repository's code could declare one and nothing for a guard to arm. That is the
// same exclusion website and control-plane make for vitest, astro and stryker, and it is a real limit
// rather than an oversight: a `go test` that exits 0 having run zero tests is a gap this gate cannot
// close, and scripts/coverage-gate.sh's package floor is what covers that case instead.
//
// THAT PARAGRAPH WAS AN ARGUMENT UNTIL, WHEN IT WAS MEASURED, and two of the six exclusions
// came back qualified. Four zero-test routes were put to the coverage gate (a build tag over every test
// file, a package with no tests, a `-run` pattern matching nothing, and `t.Skip` in every test) and it
// caught all four, so the sentence above holds for `go test`; the one case it did not hold for, a package
// whose only coverage block carries zero statements, is fixed in coverage-gate.sh. `go vet` and
// `golangci-lint` over no packages both exit 1, so neither has an examined-nothing pass. But `go build`
// over no packages exits 0 with a warning, and `gofmt` reports a file it cannot parse on stderr while
// leaving stdout empty, which the ci.yml step then read as a pass. gofmt's step now captures the status
// and floors what it walked; go build's is covered by go vet and go test in the same job. `gremlins` runs
// in no workflow at all, so nothing reads its verdict. The exclusions stay, and each one now stands on a
// measurement recorded beside the step it is about.
//
// THE DERIVATION, in order:
//   1. Invocation channels:
//        a. Makefile recipe lines, followed transitively through `$(MAKE) X` and `make X`;
//        b. every step in .github/workflows/*.yml, with YAML COMMENTS STRIPPED FIRST, because a path
//           named in CI PROSE is not an invocation. Both ci.yml and the Makefile carry long comment
//           blocks naming scripts, and counting prose as an invocation invents entry points.
//        c. a nested npm package reached by `cd <dir> && ... npm run <name>`, which is the only way
//           scripts/schema-validate/validate.mjs is ever run: no Makefile line and no workflow step
//           names the file itself.
//   2. Direct invocations only: `node <path>`, `[npx] tsx <path>`, or a shell script run as
//      `./path.sh`, `bash path.sh` or `sh path.sh`.
//   3. Entry DIRECTORIES are derived, not hardcoded: the top-level directories the derived paths live
//      in, minus the Go source trees and .github. Here that resolves to {scripts}.
//   4. Required: EVERY derived entry point in those directories, whatever it is named.
//
// THE SHELL-ONLY TOOTH. A bash EXIT trap is REPLACED by a later one, so a shell entry point that sources
// the guard and then installs its own `trap ... EXIT` has silently disarmed it while still reading as
// enrolled. That is a finding here. scripts/coverage-gate.sh had exactly that trap for its temporary
// directory, and it now defines verdict_guard_cleanup instead, which the guard calls before reporting.
//
// FAILS WHEN IT CANNOT RUN, AND FAILS WHEN THERE IS NOTHING TO CHECK: exit 2 if the Makefile or either
// guard module is unreadable, if a guard module has lost its teeth, if no workflows are found, or if the
// derivation yields no entry points, no entry directories, or fewer than the floor. A gate that silently
// checks nothing is the same bug it is here to catch.
//
// Run: node scripts/verdict-guard-gate.mjs   (or `make lint-verdict-guard`)

import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
// The gate enrols ITSELF. It is invoked by `make lint-verdict-guard` and by ci.yml exactly like every
// entry point it grades, so its own exit code is read the same way and is capable of the same silence.
// Exempting the enforcer is how an enforcer stops running without anyone noticing.
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD_MJS = "scripts/lib/verdict-guard.mjs";
const GUARD_SH = "scripts/lib/verdict-guard.sh";
// The floor is a count, not a list. It sits deliberately under the current number (7) so
// ordinary churn does not trip it, while a derivation that collapses (a Makefile rewritten in a shape
// this file does not parse, a regex that stops matching) cannot pass as "nothing to check".
const REQUIRED_FLOOR = 5;
// Go source trees and .github. The tripwire under .github is deliberately standalone and carries its own
// self-test, and it is excluded here for the same reason and by the same rule as in the sibling repos.
const NOT_ENTRY_DIRS = new Set(["cmd", "internal", "vendor", "docs", "build", "dist", "node_modules", ".github", "results"]);

function die(code, msg) {
  console.error(`verdict-guard-gate: ${msg}`);
  // A refusal is a verdict. Declared on stderr beside the reason, so the log carries one uniform line
  // and the guard does not also report an undeclared exit. 2 means "could not check", distinct from 1
  // meaning "checked and found faults".
  verdictSkipped(msg, { canonicalTo: "stderr" });
  process.exit(code);
}

/** blankComments removes comment bytes while keeping offsets, so a pattern inside a comment cannot
 * count. A scanner that reads comments as code is its own bug class, and it produced a false negative
 * in the engine's reachability gate. String literals are deliberately NOT blanked: a hand-rolled lexer
 * treats the `'` in a regex character class such as /['"]/ as the start of a string, never finds a
 * closing quote, and blanks the rest of the file, which turns a real enrolment into a reported finding.
 * The probes below anchor at statement position instead. */
function blankJsComments(src) {
  const out = Array.from(src);
  let i = 0;
  let mode = "code";
  let quote = "";
  while (i < src.length) {
    const c = src[i];
    const d = src[i + 1];
    if (mode === "code") {
      if (c === "/" && d === "/") { mode = "line"; out[i] = out[i + 1] = " "; i += 2; continue; }
      if (c === "/" && d === "*") { mode = "block"; out[i] = out[i + 1] = " "; i += 2; continue; }
      if (c === '"' || c === "'" || c === "`") { mode = "str"; quote = c; i++; continue; }
      i++;
      continue;
    }
    if (mode === "line") { if (c === "\n") mode = "code"; else out[i] = " "; i++; continue; }
    if (mode === "block") { if (c === "*" && d === "/") { out[i] = out[i + 1] = " "; mode = "code"; i += 2; continue; } if (c !== "\n") out[i] = " "; i++; continue; }
    if (mode === "str") { if (c === "\\") { i += 2; continue; } if (c === quote) mode = "code"; i++; }
  }
  return out.join("");
}

/** Shell comments, line-oriented. A `#` inside a single- or double-quoted string on the same line would
 * be blanked wrongly, so quoted runs are skipped rather than parsed. */
function blankShComments(src) {
  return src
    .split("\n")
    .map((line) => {
      let inSingle = false;
      let inDouble = false;
      for (let i = 0; i < line.length; i++) {
        const c = line[i];
        if (c === "\\") { i++; continue; }
        if (c === "'" && !inDouble) { inSingle = !inSingle; continue; }
        if (c === '"' && !inSingle) { inDouble = !inDouble; continue; }
        if (c === "#" && !inSingle && !inDouble && (i === 0 || /\s/.test(line[i - 1] ?? ""))) return line.slice(0, i);
      }
      return line;
    })
    .join("\n");
}

// ---- the guard modules must exist and still have their teeth -----------------------------------------
const GUARD_TEETH = [
  [GUARD_MJS, "an exit listener", /process\.on\(\s*["']exit["']/],
  [GUARD_MJS, "a forced non-zero exit code", /process\.exitCode\s*=\s*1/],
  [GUARD_MJS, "an exported verdictReached", /export function verdictReached/],
  [GUARD_MJS, "an exported verdictSkipped", /export function verdictSkipped/],
  [GUARD_SH, "an EXIT trap", /^\s*trap\s+__vg_on_exit\s+EXIT\s*$/m],
  [GUARD_SH, "a forced non-zero exit", /^\s*exit 1\s*$/m],
  [GUARD_SH, "a verdict_reached function", /^\s*verdict_reached\s*\(\s*\)\s*\{/m],
  [GUARD_SH, "a verdict_skipped function", /^\s*verdict_skipped\s*\(\s*\)\s*\{/m],
];
const guardSrc = new Map();
for (const rel of [GUARD_MJS, GUARD_SH]) {
  const abs = join(REPO, rel);
  if (!existsSync(abs)) die(2, `cannot check: ${rel} is missing`);
  // Blanked before the teeth are checked, and that is not tidiness. A guard's own docblock describes the
  // forced exit in prose, so against the raw source that tooth is satisfied by a COMMENT and removing
  // every real one would leave this gate reporting the guard intact.
  const raw = readFileSync(abs, "utf8");
  guardSrc.set(rel, rel.endsWith(".sh") ? blankShComments(raw) : blankJsComments(raw));
}
for (const [rel, what, re] of GUARD_TEETH) {
  if (!re.test(guardSrc.get(rel) ?? "")) die(2, `cannot check: ${rel} no longer contains ${what}, so enrolment would be meaningless`);
}

// ---- derive the entry points -------------------------------------------------------------------------
const makefilePath = join(REPO, "Makefile");
if (!existsSync(makefilePath)) die(2, "cannot check: Makefile is missing, so there is no invocation channel to derive from");
const makefileSrc = readFileSync(makefilePath, "utf8");

/** Top-level simple variable assignments, so a recipe that runs `$(GATE)` is followed to the gate.
 * A value containing `$(` is skipped rather than half-expanded: `VERSION ?= $(shell git describe ...)`
 * is not a path, and expanding it would only invent tokens. Measured: a recipe invoking an entry point
 * through a make variable was derived as nothing at all and printed the same PASS as a clean run. */
const makeVars = new Map();
for (const raw of makefileSrc.split("\n")) {
  if (/^\t/.test(raw) || /^\s*#/.test(raw)) continue;
  const m = /^([A-Za-z0-9_.-]+)\s*[:?+]?=\s*(.*)$/.exec(raw);
  if (m && !(m[2] ?? "").includes("$(")) makeVars.set(m[1] ?? "", (m[2] ?? "").trim());
}
const expandMakeVars = (line) => {
  let out = line;
  for (let i = 0; i < 4; i++) {
    const next = out.replace(/\$[({]([A-Za-z0-9_.-]+)[)}]/g, (whole, name) => (makeVars.has(name) ? (makeVars.get(name) ?? "") : whole));
    if (next === out) break;
    out = next;
  }
  return out;
};

/** target -> its recipe lines, with make's own comments removed. A recipe line is TAB-indented. */
const targets = new Map();
{
  let current = null;
  for (const raw of makefileSrc.split("\n")) {
    if (/^\t/.test(raw)) {
      if (current !== null) targets.get(current)?.push(expandMakeVars(raw.replace(/^\t/, "").replace(/^[-@+]+/, "")));
      continue;
    }
    if (/^\s*#/.test(raw) || raw.trim() === "") continue;
    const m = /^([A-Za-z0-9_.\/-]+)\s*:(?!=)/.exec(raw);
    if (m) {
      current = m[1];
      if (!targets.has(current)) targets.set(current, []);
      continue;
    }
    current = null;
  }
  targets.delete(".PHONY");
}
if (targets.size === 0) die(2, "cannot check: no make targets were parsed out of the Makefile, so the derivation has broken");

// The negative lookahead stops ".json" matching as ".js", which otherwise invents entry points out of
// every JSON path on the same command line.
const JS_TAIL = String.raw`((?:\.\/)?(?:[A-Za-z0-9_.-]+\/)+[A-Za-z0-9_.-]+\.(?:mjs|cjs|js|ts))(?![A-Za-z0-9])`;
// A FLAG THAT TAKES A MODULE PATH SWALLOWS THE PATH WITH IT. `--import`, `--require` and the loader flags
// are followed by a module, and the generic `(?:--[^\s]+\s+)*` skip consumes the flag word while leaving
// that module standing where the entry point should be. MEASURED: `node --import
// ./arm-load-recorder.mjs validate.mjs` derived the PRELOAD as the entry point and derived validate.mjs
// as nothing at all, so this gate reported a finding against a file that has no verdict to declare while
// losing the one file it had been holding to a verdict since it was written.
//
// AND WIDENING THE SKIP TO `--import\s+\S+\s+` DOES NOT FIX IT, which was also measured rather than
// assumed. The skip is greedy, so it does take the flag and its argument together, and then JS_TAIL fails
// on `validate.mjs` because JS_TAIL requires a directory separator; the engine BACKTRACKS to skipping the
// flag word alone and JS_TAIL then matches `./arm-load-recorder.mjs`, whose leading `./` satisfies its
// `(?:[A-Za-z0-9_.-]+\/)+` segment. The result is byte-identical to no fix at all. So the flag and its
// argument are REMOVED FROM THE STRING before any entry-point pattern reads it, which no amount of
// backtracking can undo.
const NODE_PRELOAD_FLAGS = String.raw`--(?:import|require|loader|experimental-loader)`;
const NODE_RE = new RegExp(String.raw`(?:^|[\s;&|(])(?:npx\s+)?(?:node|tsx)\s+(?:--[^\s]+\s+)*` + JS_TAIL, "g");
const PRELOAD_STRIP_RE = new RegExp(NODE_PRELOAD_FLAGS + String.raw`(?:=|\s+)\S+`, "g");
// AND THE PRELOAD IS NAMED RATHER THAN DROPPED, on this repository's standing rule that a derivation
// which silently discards what it saw can report on less than it claims. A preload is not an entry point:
// it is loaded INTO one, it reports no outcome of its own, and requiring it to declare a verdict would be
// requiring a verdict of something that cannot have one. For scripts/schema-validate/arm-load-recorder.mjs
// enrolling it would be worse than pointless: importing the guard from a file whose whole purpose is to
// arm a load recorder before anything else loads would load the guard first, which is the hole it closes.
const NODE_PRELOAD_RE = new RegExp(NODE_PRELOAD_FLAGS + String.raw`(?:=|\s+)(?:\.\/)?((?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+\.(?:mjs|cjs|js|ts))(?![A-Za-z0-9])`, "g");
// A shell gate is run either by path (`./scripts/x.sh`) or through an interpreter (`bash scripts/x.sh`).
const SH_RE = /(?:^|[\s;&|(])(?:(?:bash|sh)\s+)?(\.\/(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+\.sh|(?:bash|sh)\s+(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+\.sh)/g;

// A BARE RELATIVE PATH AT COMMAND POSITION. `run: scripts/x.sh` is an ordinary, working GitHub Actions
// step and `run: scripts/x.mjs` is an ordinary shebang invocation, and neither carries `./`, `bash ` or
// `node `, so neither of the two patterns above sees them. Measured: a gate script with no
// completion guard at all, invoked in either shape, was derived as NOTHING and this file printed the
// byte-identical `VERDICT GUARD GATE PASS (8 entry points, all enrolled, all able to fail)` it printed
// on a clean run at that time; the count is nine since scripts/fuzz-bounded.sh was added. An unenrolled
// gate that the enrolment gate cannot see is the exact defect this file exists to catch.
//
// COMMAND POSITION IS WHAT KEEPS IT PRECISE. The two patterns above accept any preceding whitespace, so
// they read an ARGUMENT as an invocation; a bare path may not. The line is split on the shell's own
// separators and only the FIRST token of a segment is considered, after leading `exec`, `sudo`, `time`,
// `env` and `NAME=value` prefixes are stripped. That is why `chmod +x scripts/x.sh`, `gofmt -l
// scripts/x.sh` and `shellcheck scripts/x.sh` are not invocations here: the path is not the command.
const BARE_ENTRY_RE = /^(?:\.\/)?(?:[A-Za-z0-9_.-]+\/)+[A-Za-z0-9_.-]+\.(?:sh|mjs|cjs|js|ts)$/;
// `run:` is stripped because a workflow is scanned as one blob rather than step by step, so a one-line
// `run: scripts/x.sh` arrives with the YAML key still attached. Only `run:` is stripped, so
// `cache-dependency-path: scripts/schema-validate/package-lock.json` and every other key keep their key
// as the first token and cannot be read as a command.
const COMMAND_PREFIX_RE = /^(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+|exec\s+|sudo\s+|time\s+|env\s+|run:\s*|[-@+]+)/;

/** scanBarePaths records a relative script path that stands at command position in `s`. */
function scanBarePaths(s, where) {
  for (const rawSegment of String(s).split(/\n|;|&&|\|\||\||\(|\)|`|\$\{|\}/)) {
    let seg = rawSegment.trim();
    for (let i = 0; i < 4; i++) {
      const next = seg.replace(COMMAND_PREFIX_RE, "").trim();
      if (next === seg) break;
      seg = next;
    }
    const first = seg.split(/\s+/)[0] ?? "";
    if (BARE_ENTRY_RE.test(first)) record(first, where);
  }
}

const direct = new Map(); // repo-relative path -> Set(where)
const record = (p, where) => {
  const rel = p.replace(/^\.\//, "").replace(/^(?:bash|sh)\s+/, "");
  if (!direct.has(rel)) direct.set(rel, new Set());
  direct.get(rel).add(where);
};

const preloads = new Map(); // repo-relative path -> Set(where)
const recordPreload = (p, where) => {
  const rel = p.replace(/^\.\//, "");
  if (!preloads.has(rel)) preloads.set(rel, new Set());
  preloads.get(rel).add(where);
};

function scanCommand(cmd, where, seen = new Set()) {
  const raw = String(cmd);
  // Preloads are read off the untouched string, then removed from it, so what remains is the entry point.
  for (const m of raw.matchAll(NODE_PRELOAD_RE)) recordPreload(m[1] ?? "", where);
  const s = raw.replace(PRELOAD_STRIP_RE, " ");
  for (const m of s.matchAll(NODE_RE)) record(m[1] ?? "", where);
  for (const m of s.matchAll(SH_RE)) record(m[1] ?? "", where);
  scanBarePaths(s, where);
  // Transitive make targets.
  for (const m of s.matchAll(/(?:\$\(MAKE\)|make)\s+([A-Za-z0-9_.\/-]+)/g)) {
    const name = m[1] ?? "";
    if (seen.has(`make:${name}`)) continue;
    seen.add(`make:${name}`);
    for (const line of targets.get(name) ?? []) scanCommand(line, `${where} -> make ${name}`, seen);
  }
  // A nested npm package, reached only through `cd <dir> && ... npm run <name>`. Without this channel
  // scripts/schema-validate/validate.mjs is named nowhere the derivation looks and would be exempt by
  // accident rather than by decision.
  const cdMatch = /(?:^|[\s;&|(])cd\s+([A-Za-z0-9_.\/-]+)/.exec(s);
  if (cdMatch) {
    const pkgDir = cdMatch[1] ?? "";
    const pkgPath = join(REPO, pkgDir, "package.json");
    if (existsSync(pkgPath)) {
      const nested = JSON.parse(readFileSync(pkgPath, "utf8")).scripts ?? {};
      for (const m of s.matchAll(/npm\s+run\s+(?:--silent\s+|-s\s+)?([A-Za-z0-9:_-]+)/g)) {
        const name = m[1] ?? "";
        const body = nested[name];
        if (body === undefined || seen.has(`${pkgDir}:${name}`)) continue;
        seen.add(`${pkgDir}:${name}`);
        // Rewritten to the repo-relative form, because the nested script's paths are relative to its
        // own directory and a bare `node validate.mjs` would otherwise be recorded at the repo root.
        // The nested script's paths are relative to its own directory, so a preload is read off the
        // untouched body and then removed from it exactly as in scanCommand, and both are rewritten to
        // the repo-relative form. Without the removal a bare `node validate.mjs` would be recorded at the
        // repo root, and with a `--import` flag in front of it the preload would be recorded as the entry.
        const nestedBody = String(body);
        for (const mm of nestedBody.matchAll(NODE_PRELOAD_RE)) recordPreload(`${pkgDir}/${mm[1] ?? ""}`, `${where} -> ${pkgDir} npm run ${name}`);
        const nestedStripped = nestedBody.replace(PRELOAD_STRIP_RE, " ");
        for (const mm of nestedStripped.matchAll(NODE_RE)) record(`${pkgDir}/${(mm[1] ?? "").replace(/^\.\//, "")}`, `${where} -> ${pkgDir} npm run ${name}`);
        // The bare-filename form, which JS_TAIL cannot match because it requires a directory separator.
        for (const mm of nestedStripped.matchAll(/(?:^|[\s;&|(])(?:npx\s+)?(?:node|tsx)\s+(?:--[^\s]+\s+)*([A-Za-z0-9_.-]+\.(?:mjs|cjs|js|ts))(?![A-Za-z0-9])/g)) {
          record(`${pkgDir}/${mm[1] ?? ""}`, `${where} -> ${pkgDir} npm run ${name}`);
        }
      }
    }
  }
}

for (const [name, lines] of targets) for (const line of lines) scanCommand(line, `make:${name}`);

const wfDir = join(REPO, ".github", "workflows");
const workflows = existsSync(wfDir) ? readdirSync(wfDir).filter((f) => /\.ya?ml$/.test(f)) : [];
if (workflows.length === 0) die(2, "cannot check: no .github/workflows/*.yml found, so CI reachability cannot be derived");
/** dispatchOnly is reported rather than enforced: a gate in a workflow with no push, pull_request or
 * schedule trigger does not run on a push, which is a fact a reader of this output needs. */
const dispatchOnly = [];
for (const wf of workflows) {
  const raw = readFileSync(join(wfDir, wf), "utf8");
  const onBlock = [];
  let inOn = false;
  for (const line of raw.split("\n")) {
    if (/^on:/.test(line)) { inOn = true; continue; }
    if (inOn) { if (/^[A-Za-z]/.test(line)) { inOn = false; continue; } onBlock.push(line); }
  }
  const t = onBlock.join("\n");
  if (!/^\s{2}push:/m.test(t) && !/^\s{2}pull_request:/m.test(t) && !/^\s{2}schedule:/m.test(t)) dispatchOnly.push(wf);
  const stripped = raw.split("\n").map((l) => l.replace(/(^|\s)#.*$/, "$1")).join("\n");
  scanCommand(stripped, `ci:${wf}`);
}

if (direct.size === 0) die(2, "cannot check: the derivation found no directly-invoked scripts at all");

// ---- derive the entry directories --------------------------------------------------------------------
const entryDirs = new Set();
for (const p of direct.keys()) {
  const top = p.split("/")[0];
  if (!NOT_ENTRY_DIRS.has(top)) entryDirs.add(top);
}
if (entryDirs.size === 0) die(2, "cannot check: no entry directories were derived, so the required set would be empty by construction");

const required = [];
const missingFromDisk = [];
const outsideEntryDirs = [];
for (const [p, where] of [...direct.entries()].sort()) {
  const abs = join(REPO, p);
  if (!existsSync(abs)) { missingFromDisk.push(p); continue; }
  if (!entryDirs.has(p.split("/")[0])) { outsideEntryDirs.push(p); continue; }
  const raw = readFileSync(abs, "utf8");
  const isShell = p.endsWith(".sh");
  required.push({ path: p, raw, code: isShell ? blankShComments(raw) : blankJsComments(raw), isShell, where: [...where] });
}

if (required.length === 0) die(2, "cannot check: no entry points were derived inside the entry directories, so there is nothing to check");
if (required.length < REQUIRED_FLOOR) {
  die(2, `cannot check: only ${required.length} entry point(s) were derived, under the floor of ${REQUIRED_FLOOR}. The derivation has broken, or the make chain has been gutted.`);
}

// ---- the three findings ------------------------------------------------------------------------------
const unenrolled = [];
const cannotFail = [];
const disarmed = [];
// Both probes are ANCHORED AT STATEMENT POSITION. A bare substring match reported a gate as enrolled in
// the sibling website repo when the only mention was a constant naming the guard and an advice string
// printing the call, so anchoring to the start of a line is what makes these sound rather than plausible.
const IMPORTS_MJS = /^[ \t]*import\s*\{[^}]*\}\s*from\s*["'][^"']*verdict-guard\.mjs["']/m;
const DECLARES_MJS = /^[ \t]*(?:verdictReached|verdictSkipped)\s*\(/m;
const SOURCES_SH = /^[ \t]*(?:\.|source)\s+.*verdict-guard\.sh/m;
const DECLARES_SH = /^[ \t]*(?:verdict_reached|verdict_skipped)\s+/m;
// A shell entry point can fail through an explicit non-zero exit, or through a counted declaration:
// verdict_reached hands the guard a number and the guard forces exit 1 on a positive one.
const FAILS_SH = /^[ \t]*exit\s+[^0\s]|^[ \t]*verdict_reached\s+\S+\s+\S/m;
const FAILS_MJS = /process\.exit\(\s*[^0\s]|process\.exitCode\s*=|(^|\s)throw\s|^[ \t]*verdictReached\s*\([^)]*,[^)]/m;
// The shell-only tooth: an EXIT trap installed by the script REPLACES the guard's, silently disarming it.
const OWN_EXIT_TRAP = /^[ \t]*trap\s+[^\n]*\bEXIT\b/m;

for (const r of required) {
  const sources = r.isShell ? SOURCES_SH.test(r.code) : IMPORTS_MJS.test(r.code);
  const declares = r.isShell ? DECLARES_SH.test(r.code) : DECLARES_MJS.test(r.code);
  if (!sources || !declares) unenrolled.push({ ...r, sources, declares });
  if (!(r.isShell ? FAILS_SH : FAILS_MJS).test(r.code)) cannotFail.push(r);
  if (r.isShell && sources && OWN_EXIT_TRAP.test(r.code)) disarmed.push(r);
}

console.log(
  `verdict-guard-gate: ${direct.size} directly-invoked script(s) derived from ${targets.size} make target(s) and ${workflows.length} workflow(s), ${required.length} of them inside the derived entry directories {${[...entryDirs].sort().join(", ")}}`,
);
console.log(`  guard modules: ${GUARD_MJS} and ${GUARD_SH}, both present with their teeth intact`);
const shellCount = required.filter((r) => r.isShell).length;
console.log(`  ${shellCount} shell entry point(s) and ${required.length - shellCount} node entry point(s) required`);
console.log(`  not required, because the tool reports its own verdict: go test, go vet, go build, gofmt, golangci-lint, gremlins`);
if (missingFromDisk.length) console.log(`  derived but not on disk (not required): ${missingFromDisk.join(", ")}`);
if (outsideEntryDirs.length) console.log(`  derived but outside the entry directories (not required): ${outsideEntryDirs.join(", ")}`);
console.log(`  workflows with no push, pull_request or schedule trigger, so they do NOT run on a push: ${dispatchOnly.length ? dispatchOnly.join(", ") : "(none)"}`);
const preloadList = [...preloads.entries()].sort();
console.log(
  `  derived as preloads rather than entry points, so no verdict is required of them: ${preloadList.length ? preloadList.map(([p, w]) => `${p} (loaded into ${[...w].join(", ")})`).join("; ") : "(none)"}`,
);
// A PRELOAD THAT IS NOT THERE IS A FINDING AND NOT A REFUSAL, because the command line says it will be
// loaded and it will not be. node fails at startup on a `--import` that does not resolve, so the run this
// gate is reasoning about cannot happen at all.
const missingPreloads = preloadList.filter(([p]) => !existsSync(join(REPO, p)));

let bad = 0;
if (missingPreloads.length) {
  bad += missingPreloads.length;
  console.log(`\n  ${missingPreloads.length} preload(s) named on a command line are not on disk, so the run cannot start:`);
  for (const [p, w] of missingPreloads) console.log(`    ${p}  (loaded into ${[...w].join(", ")})`);
}
if (cannotFail.length) {
  bad += cannotFail.length;
  console.log(`\n  ${cannotFail.length} entry point(s) have NO failure path at all, so they cannot fail for any reason:`);
  for (const r of cannotFail) console.log(`    ${r.path}  (invoked by ${r.where.join(", ")})`);
}
if (disarmed.length) {
  bad += disarmed.length;
  console.log(`\n  ${disarmed.length} shell entry point(s) source the guard and then install their own EXIT trap, which REPLACES it:`);
  for (const r of disarmed) console.log(`    ${r.path}  (invoked by ${r.where.join(", ")})`);
  console.log(`\n  Define a function called verdict_guard_cleanup instead. ${GUARD_SH} runs it before reporting.`);
}
if (unenrolled.length) {
  bad += unenrolled.length;
  console.log(`\n  ${unenrolled.length} entry point(s) are NOT enrolled in a completion guard:`);
  for (const r of unenrolled) {
    const guard = r.isShell ? GUARD_SH : GUARD_MJS;
    const why = !r.sources ? `does not ${r.isShell ? "source" : "import"} ${guard}` : "reaches the guard but never declares a verdict";
    console.log(`    ${r.path}  ${why}  (invoked by ${r.where.join(", ")})`);
  }
  console.log(`\n  Enrol a shell gate with two lines: . "$(cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)/lib/verdict-guard.sh"`);
  console.log(`  and verdict_reached <failures> <count> immediately before the exit that reports the outcome.`);
  console.log(`  Enrol a node gate the same way with import { verdictReached } from "./lib/verdict-guard.mjs";`);
  console.log(`  Where the precondition is genuinely absent, declare the skip and its reason instead.`);
}

if (bad > 0) {
  console.log(`\nVERDICT GUARD GATE: ${bad} finding(s)`);
  verdictReached(bad, required.length);
  process.exit(1);
}
console.log(`\nVERDICT GUARD GATE PASS (${required.length} entry points, all enrolled, all able to fail)`);
verdictReached(0, required.length);
