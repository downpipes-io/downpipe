#!/usr/bin/env node

/**
 * Writing-rules linter: em dashes and en dashes, over the whole file.
 *
 * House style binds this workspace: Australian English, no em dashes, no rule-of-three, precise
 * claims. It was binding here and graded by NOTHING.
 *
 * THIS REPOSITORY WAS RECORDED AS HAVING ZERO VIOLATIONS AND IT DOES NOT. That reading came from a
 * corpus of .ts/.js/.md files, which matches 114 of this repository's 1,066 tracked files and NONE of
 * the 216 .go files that are the product. Re-measured over the language this repository is actually
 * written in, it holds 44 em dashes across 14 files, twelve of them .go, and three of those are not
 * test files: cmd/downpipe/main.go, internal/format/verify.go and internal/restore/restore.go. A gate
 * scoped to the extensions a Go repository barely uses is a gate that reports clean by construction.
 *
 * WHERE THEY ARE, classified rather than eyeballed. All 44 were tagged with a code/comment/string
 * reader: 44 comments, 0 strings, 0 code. So none is in a customer-facing message, an error string or
 * a CLI output line, and nothing here needs fixing on sight. They are prose explaining this
 * repository's own code, and they DO travel, because this repository's source is distributed. That is
 * an argument for grading new work here, not for rewriting 44 dense comments to clear a number.
 *
 * PORTED FROM engine/scripts/writing-rules-source.mjs, whose baseline shape this copies: a ledger of
 * debt that fails in FOUR directions, not a list of exemptions. Two things are deliberately different:
 *
 *   - The banned-word and claim rules are NOT copied. They are engine-specific, and inventing scope
 *     for a repository this size would be a gate nobody asked for.
 *   - The needles are built from CODE POINTS rather than typed, so this file contains neither
 *     character and needs no structural entry excusing itself in its own baseline. The engine copy
 *     needs exactly such an entry. A detector that must be exempted from itself is a small hole, and
 *     it costs one line to not have it.
 *
 * Dashes are checked over the WHOLE file. They never appear in code syntax, only in comments, string
 * literals and prose, and house style bans them in all three.
 *
 * Usage:  node scripts/writing-rules-source.mjs [root ...]
 *         node scripts/writing-rules-source.mjs --self-test
 *         node scripts/writing-rules-source.mjs [root ...] --write-baseline
 * Exit:   0 clean, 1 violations, 2 could-not-check. Exit 2 covers a named root that is absent, a run
 *         that matched no file at all, an unknown flag, and a baseline that is missing or malformed.
 *         "Checked nothing" must never read the same as "checked and found nothing".
 */

import { readFileSync, writeFileSync, readdirSync, statSync, mkdtempSync, rmSync, mkdirSync } from "node:fs";
import { join, relative, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
// This repository requires every script entry point it runs to be enrolled in the shared completion
// guard, enforced by scripts/verdict-guard-gate.mjs via `make lint-verdict-guard`. The guard closes the
// class where an entry point reaches exit 0 without ever reaching its own verdict, so nothing in the run
// was capable of failing. Every terminal path below declares one: verdictReached for checked-and-found,
// verdictSkipped for could-not-check, which keeps exit 2 distinct from exit 1.
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..");
const BASELINE_REL = "scripts/writing-rules-baseline.json";

/** Built from code points so this file carries neither character. */
const RULES = [
  { rule: "em-dash", ch: String.fromCodePoint(0x2014) },
  { rule: "en-dash", ch: String.fromCodePoint(0x2013) },
];

// .go first, because it is the product and the reason the previous reading was wrong.
const DEFAULT_EXTS = [".go", ".md", ".mjs", ".js", ".sh", ".yml", ".yaml", ".toml"];
const SKIP_DIRS = new Set(["node_modules", "dist", ".git", ".wrangler", "build", "coverage", ".worktrees"]);

const KNOWN_FLAGS = new Set(["--self-test", "--write-baseline", "--exts"]);

/** An unrecognised flag is a refusal, never a silent ignore: the run the caller asked for did not happen. */
function unknownFlags(argv) {
  return argv.filter((a) => a.startsWith("--") && a !== "--" && !KNOWN_FLAGS.has(a.split("=")[0]));
}

function* walk(dir, exts) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    if (err.code === "ENOENT") return;
    throw err;
  }
  for (const entry of entries) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      yield* walk(p, exts);
    } else if (entry.isFile() && exts.some((e) => p.endsWith(e))) {
      yield p;
    }
  }
}

/**
 * Count OCCURRENCES, not lines, and read the file as a Buffer.
 *
 * Both halves of that sentence are scar tissue. A line-oriented reader reports a line that holds three
 * dashes as one hit, so a baseline built from it under-counts and a cleanup that removes two of the
 * three still reads as unchanged. And a shell `grep` in this workspace was proven to skip a NUL-bearing
 * file entirely while still exiting 0, hiding five of that file's eight hits. Bytes and a substring
 * index have neither failure mode.
 */
function scanFile(abs, root, hits) {
  const rel = relative(root, abs);
  const buf = readFileSync(abs);
  const src = buf.toString("utf8");
  const lines = [];
  for (const { rule, ch } of RULES) {
    let at = src.indexOf(ch, 0);
    while (at !== -1) {
      lines.push({ rule, index: at });
      at = src.indexOf(ch, at + 1);
    }
  }
  if (lines.length === 0) return;
  // One pass for line numbers rather than a rescan per hit, which is quadratic on a large tree.
  const lineAt = new Map();
  let line = 1;
  const wanted = new Set(lines.map((h) => h.index));
  for (let i = 0; i < src.length; i++) {
    if (wanted.has(i)) lineAt.set(i, line);
    if (src[i] === "\n") line += 1;
  }
  for (const h of lines) hits.push({ file: rel, line: lineAt.get(h.index) ?? 0, rule: h.rule });
}

function collect(roots, exts, root) {
  const hits = [];
  let scanned = 0;
  for (const r of roots) {
    const abs = join(root, r);
    let st;
    try {
      st = statSync(abs);
    } catch (err) {
      if (err.code !== "ENOENT") throw err;
      return { error: `root '${r}' does not exist, so nothing under it was checked.` };
    }
    if (st.isFile()) {
      if (exts.some((e) => abs.endsWith(e))) {
        scanFile(abs, root, hits);
        scanned += 1;
      }
      continue;
    }
    for (const abs2 of walk(abs, exts)) {
      scanFile(abs2, root, hits);
      scanned += 1;
    }
  }
  return { hits, scanned };
}

function observedOf(hits) {
  const observed = new Map();
  for (const h of hits) {
    if (!observed.has(h.file)) observed.set(h.file, new Map());
    const m = observed.get(h.file);
    m.set(h.rule, (m.get(h.rule) ?? 0) + 1);
  }
  return observed;
}

/**
 * THE BASELINE IS A LEDGER OF DEBT, NOT A LIST OF EXEMPTIONS. It fails in FOUR directions:
 *
 *   - MORE hits than recorded fails. New work is graded at full strength.
 *   - hits with NO entry at all fails. A new file cannot quietly join the debt.
 *   - FEWER hits than recorded ALSO fails, asking for the number to be lowered. An unbanked cleanup
 *     leaves slack behind it, and slack is how a ratchet turns back into a ceiling.
 *   - an entry whose file is gone, or which records a rule the file no longer breaks, fails as
 *     DANGLING. A stored reference outliving its target is a repeat bug shape in this workspace.
 */
function compare(observed, entries, hits) {
  const findings = [];
  const linesFor = (file, rule) =>
    hits.filter((h) => h.file === file && h.rule === rule).slice(0, 6).map((h) => h.line).join(", ");

  for (const [file, rules] of observed) {
    for (const [rule, count] of rules) {
      const allowed = entries.get(file)?.counts?.[rule] ?? 0;
      if (count > allowed) findings.push(`  NEW  ${file} [${rule}] ${count} found, ${allowed} recorded. Lines: ${linesFor(file, rule)}`);
      else if (count < allowed) findings.push(`  BANK ${file} [${rule}] ${count} found but ${allowed} recorded. Lower the number in ${BASELINE_REL}.`);
    }
  }
  for (const [file, entry] of entries) {
    for (const rule of Object.keys(entry.counts)) {
      if (!observed.get(file)?.has(rule)) {
        findings.push(`  DANGLING ${file} [${rule}] is recorded but the file no longer breaks that rule. Remove the entry.`);
      }
    }
  }
  return findings.sort();
}

function readBaseline(path) {
  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    if (err.code === "ENOENT") return { error: `${BASELINE_REL} is missing, so nothing could be compared against it.` };
    throw err;
  }
  let doc;
  try {
    doc = JSON.parse(raw);
  } catch (err) {
    return { error: `${BASELINE_REL} is not valid JSON (${err.message}).` };
  }
  const entries = new Map();
  for (const [file, entry] of Object.entries(doc.entries ?? {})) {
    if (!entry || typeof entry.counts !== "object" || typeof entry.why !== "string" || entry.why.trim() === "") {
      return { error: `${BASELINE_REL} entry '${file}' needs both a counts object and a why.` };
    }
    entries.set(file, entry);
  }
  return { entries };
}

/** The whole run, returning a code rather than calling process.exit, so the self-test can drive every branch. */
function run({ roots, exts, root, baselinePath, write }) {
  const got = collect(roots, exts, root);
  if (got.error) return { code: 2, scanned: 0, out: [`writing-rules-source: ${got.error}`] };
  if (got.scanned === 0) {
    return { code: 2, scanned: 0, out: [`writing-rules-source: 0 files matched under ${roots.join(", ")}, so this check proved nothing.`] };
  }
  const observed = observedOf(got.hits);

  if (write) {
    const files = [...observed.keys()].sort();
    const entries = {};
    for (const file of files) {
      const counts = {};
      for (const [rule, n] of [...observed.get(file).entries()].sort()) counts[rule] = n;
      entries[file] = { counts, why: "Pre-existing when this repository's first house-style gate landed. Debt to rewrite, not an exemption." };
    }
    writeFileSync(
      baselinePath,
      `${JSON.stringify(
        {
          $schema_note:
            "Recorded house-style debt. counts are EXACT: more fails as a regression, fewer fails as an unbanked cleanup, and an entry whose file or rule is gone fails as dangling. See the header of scripts/writing-rules-source.mjs.",
          generated_against: `${got.hits.length} hit(s) across ${files.length} file(s) of ${got.scanned} scanned`,
          entries,
        },
        null,
        2,
      )}\n`,
    );
    return { code: 0, scanned: got.scanned, out: [`writing-rules-source: baseline written, ${got.hits.length} recorded across ${files.length} file(s)`] };
  }

  const base = readBaseline(baselinePath);
  if (base.error) return { code: 2, scanned: got.scanned, out: [`writing-rules-source: ${base.error}`] };
  const findings = compare(observed, base.entries, got.hits);
  const debt = [...base.entries.values()].reduce((s, e) => s + Object.values(e.counts).reduce((a, b) => a + b, 0), 0);

  if (findings.length === 0) {
    // The outstanding number is printed on EVERY green run. Debt that is never quoted is debt that is
    // never paid, and the point of recording it rather than excusing it is that it stays a number
    // somebody has to look at.
    return {
      code: 0,
      scanned: got.scanned,
      out: [`writing-rules-source: 0 NEW violations across ${got.scanned} file(s); ${debt} pre-existing recorded in ${BASELINE_REL} across ${base.entries.size} file(s)`],
    };
  }
  return {
    code: 1,
    scanned: got.scanned,
    out: [
      `writing-rules-source: ${findings.length} finding(s) against ${BASELINE_REL}`,
      "",
      ...findings,
      "",
      "House style bans these characters everywhere in this workspace. Rewrite the line: a comma, a colon,",
      'parentheses, "to" for a numeric range, or a full stop.',
    ],
  };
}

/* -------------------------------------------------------------------------- */

function selfTest() {
  const checks = [];
  const ok = (name, got, want) => checks.push({ name, got, want, pass: JSON.stringify(got) === JSON.stringify(want) });
  const EM = RULES[0].ch;
  const bed = mkdtempSync(join(tmpdir(), "writing-rules-selftest-"));
  const baseline = join(bed, "baseline.json");

  const tree = (files) => {
    const root = mkdtempSync(join(bed, "tree-"));
    for (const [rel, body] of Object.entries(files)) {
      mkdirSync(join(root, dirname(rel)), { recursive: true });
      writeFileSync(join(root, rel), body);
    }
    return root;
  };
  const pin = (entries) =>
    writeFileSync(baseline, JSON.stringify({ entries: Object.fromEntries(Object.entries(entries).map(([f, c]) => [f, { counts: c, why: "test" }])) }));
  const go = (root) => run({ roots: ["src"], exts: [".ts", ".md"], root, baselinePath: baseline, write: false });

  try {
    // CONTROL 1: observed matches the pin exactly. This must PASS, and without it every attack below
    // could be passing for the wrong reason (a gate that always fails rejects every mutant too).
    let root = tree({ "src/a.ts": `x ${EM} y` });
    pin({ "src/a.ts": { "em-dash": 1 } });
    ok("C1 a tree matching its pin exits 0", go(root).code, 0);

    // CONTROL 2: a clean tree with an empty pin passes.
    root = tree({ "src/a.ts": "no dashes here" });
    pin({});
    ok("C2 a clean tree with an empty baseline exits 0", go(root).code, 0);

    // DIRECTION 1: MORE than recorded.
    root = tree({ "src/a.ts": `x ${EM} y ${EM} z` });
    pin({ "src/a.ts": { "em-dash": 1 } });
    let r = go(root);
    ok("D1 more hits than recorded exits 1", r.code, 1);
    ok("D1 names it as NEW", r.out.some((l) => l.includes("NEW") && l.includes("2 found, 1 recorded")), true);

    // DIRECTION 2: FEWER than recorded, the unbanked cleanup.
    root = tree({ "src/a.ts": `x ${EM} y` });
    pin({ "src/a.ts": { "em-dash": 3 } });
    r = go(root);
    ok("D2 fewer hits than recorded exits 1", r.code, 1);
    ok("D2 names it as BANK", r.out.some((l) => l.includes("BANK")), true);

    // DIRECTION 3: hits with NO entry at all.
    root = tree({ "src/new.ts": `x ${EM} y` });
    pin({});
    r = go(root);
    ok("D3 a new file joining the debt exits 1", r.code, 1);
    ok("D3 names it as NEW against 0 recorded", r.out.some((l) => l.includes("NEW") && l.includes("1 found, 0 recorded")), true);

    // DIRECTION 4: an entry whose rule the file no longer breaks.
    root = tree({ "src/a.ts": "clean now" });
    pin({ "src/a.ts": { "em-dash": 2 } });
    r = go(root);
    ok("D4 a dangling entry exits 1", r.code, 1);
    ok("D4 names it as DANGLING", r.out.some((l) => l.includes("DANGLING")), true);

    // COUNTING: occurrences, not lines. Three on ONE line is three.
    root = tree({ "src/a.ts": `${EM}${EM}${EM}\n` });
    pin({ "src/a.ts": { "em-dash": 3 } });
    ok("counts occurrences, not lines", go(root).code, 0);
    pin({ "src/a.ts": { "em-dash": 1 } });
    ok("one-per-line would have been wrong and is caught", go(root).code, 1);

    // A NUL ahead of the hits must not hide them. This is the exact instrument failure that made a
    // shell grep report 0 for a file holding 8.
    root = tree({ "src/a.ts": `${EM}${EM}${EM}${String.fromCodePoint(0)}${EM}${EM}${EM}${EM}${EM}` });
    pin({ "src/a.ts": { "em-dash": 8 } });
    ok("a NUL does not hide the hits after it", go(root).code, 0);

    // The en dash is graded separately from the em dash.
    root = tree({ "src/a.ts": `x ${RULES[1].ch} y` });
    pin({ "src/a.ts": { "en-dash": 1 } });
    ok("en dash is its own rule", go(root).code, 0);
    pin({ "src/a.ts": { "em-dash": 1 } });
    ok("an en dash does not satisfy an em-dash pin", go(root).code, 1);

    // COULD-NOT-CHECK, all of which must be 2 rather than 0. "Checked nothing" is the failure this
    // whole campaign is about.
    root = tree({ "src/a.ts": "clean" });
    pin({});
    ok("an absent root exits 2", run({ roots: ["nope"], exts: [".ts"], root, baselinePath: baseline, write: false }).code, 2);
    ok("a run matching no file exits 2", run({ roots: ["src"], exts: [".nomatch"], root, baselinePath: baseline, write: false }).code, 2);
    writeFileSync(baseline, "{ not json");
    ok("a malformed baseline exits 2", go(root).code, 2);
    rmSync(baseline);
    ok("a missing baseline exits 2", go(root).code, 2);
    pin({});
    writeFileSync(baseline, JSON.stringify({ entries: { "src/a.ts": { counts: { "em-dash": 1 } } } }));
    ok("a baseline entry with no why exits 2", go(root).code, 2);

    // An unknown flag is a refusal.
    ok("an unknown flag is reported", unknownFlags(["--nope", "src"]), ["--nope"]);
    ok("a known flag is not", unknownFlags(["--self-test", "--exts=.ts"]), []);
  } finally {
    rmSync(bed, { recursive: true, force: true });
  }

  let failed = 0;
  for (const c of checks) {
    if (!c.pass) failed += 1;
    console.log(`${c.pass ? "ok  " : "FAIL"} ${c.name}: got ${JSON.stringify(c.got)} want ${JSON.stringify(c.want)}`);
  }
  console.log(`writing-rules-source self-test: ${checks.length - failed}/${checks.length} passed`);
  return { failures: failed, checks: checks.length };
}

/* -------------------------------------------------------------------------- */

const argv = process.argv.slice(2);
const bad = unknownFlags(argv);
if (bad.length) {
  console.error(`writing-rules-source: unrecognised flag(s): ${bad.join(", ")}. The run you asked for did not happen.`);
  process.exit(2);
}

if (argv.includes("--self-test")) {
  // The self-test is an entry path like any other, so it declares its own verdict. Without this the
  // completion guard refuses the run, which is correct: a self-test that exits without a verdict is the
  // exact shape the guard exists to catch, and it caught this one.
  const { failures, checks } = selfTest();
  verdictReached(failures, checks);
  process.exit(failures === 0 ? 0 : 1);
}

const extArg = argv.find((a) => a.startsWith("--exts="));
const exts = extArg ? extArg.slice("--exts=".length).split(",") : DEFAULT_EXTS;
const roots = argv.filter((a) => !a.startsWith("--"));
if (roots.length === 0) {
  console.error("writing-rules-source: no root given, so there was nothing to check.");
  process.exit(2);
}
const result = run({
  roots,
  exts,
  root: REPO,
  baselinePath: join(HERE, "writing-rules-baseline.json"),
  write: argv.includes("--write-baseline"),
});
for (const line of result.out) (result.code === 0 ? console.log : console.error)(line);

// EXIT 2 IS COULD-NOT-CHECK AND MUST NOT COLLAPSE INTO 1. A missing root, a run that matched no file and
// a malformed baseline all mean the check the caller asked for did not happen, which is a different fact
// from the check running and finding something. verdictSkipped declares a verdict without forcing 1, so
// the guard is satisfied and the 2 survives.
if (result.code === 2) {
  verdictSkipped(result.out.join(" ").slice(0, 200));
  process.exit(2);
}
verdictReached(result.code === 0 ? 0 : 1, result.scanned);
process.exit(result.code);
