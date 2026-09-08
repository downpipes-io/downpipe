#!/usr/bin/env node
// Validates the on-disk downpipe/0.1.0 conformance vector manifests against
// docs/format/schema.json using ajv (SPEC.md section 14). Never edits a vector
// or weakens SPEC.md: the schema describes the frozen downpipe/0.1.0 wire format,
// and this checker confirms every structurally valid manifest matches it while
// the deliberately malformed negative vectors are rejected exactly where SPEC.md
// says a reader rejects them.
//
// Scope. The schema can validate only the cleartext JSON the format exposes on
// disk: the root manifest (run/<runId>/root.manifest.json) and each RUNLOG line
// (_RECOVERY/RUNLOG). The shard preamble and record lines live inside the
// encrypted .dpe containers (downpipe STREAM, AES-256-GCM) and are not on disk in
// the clear, so their ShardPreamble and ShardRecord shapes are validated by the
// Go reference reader and its unit tests, not here.
//
// A handful of negative vectors mutate the manifest into a shape the schema can
// and must reject (an unknown major, an out-of-range count number, a dropped
// break-glass flag). Those are listed in EXPECT_SCHEMA_INVALID with the SPEC.md
// rule they violate, and the checker asserts they fail rather than pass. Every
// other manifest, including the negatives whose defect is canonical form,
// signature, a cross-field rule or a byte-level mutation the schema deliberately
// does not express, must pass the schema.
//
// A smaller set of negative vectors mutate the manifest into bytes that are not
// valid JSON at all (RFC 8259 syntax, not a schema shape), so ajv is never
// reached: encoding/json, and every conformant parser, refuses to decode them
// before any schema or application check runs. Those are listed in
// EXPECT_JSON_SYNTAX_INVALID and asserted to fail JSON.parse rather than being
// treated as an unparseable-manifest bug in the vector.
//
// Run with: npm ci && npm run validate (from this directory), or via
// scripts/schema-validate in the Makefile / CI schema-validate job.

import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const requireHere = createRequire(import.meta.url);
const SELF_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(SELF_DIR, "..", "..");
const SCHEMA_PATH = path.join(REPO_ROOT, "docs", "format", "schema.json");
const VECTORS_DIR = path.join(REPO_ROOT, "internal", "format", "testdata", "vectors");
const AJV_MODULE = "ajv/dist/2020.js";

// Negative vectors whose root manifest is intentionally a shape the schema can
// and must reject. The reason names the SPEC.md rule.
const EXPECT_SCHEMA_INVALID = {
  "unknown-major": "formatVersion is downpipe/9.0.0, not the const downpipe/0.1.0 (SPEC.md 13, 14.3)",
  "unimplemented-minor": "formatVersion is downpipe/0.2.0, not the const downpipe/0.1.0 (SPEC.md 13, 14.3)",
  "unknown-codec": "envelope.codec is zstd, outside the closed {none, gzip} enum (SPEC.md 5.2, 14.3)",
  "count-over-2pow53": "declaredRecordCount is the JSON number 9007199254740993, above 2^53-1 (SPEC.md 11.3, 14.3)",
  "missing-break-glass": "breakGlassPresent is false and no break-glass recipient is present (SPEC.md 5.2, 14.3)",
  "negative-count": "declaredRecordCount is the JSON number -1; a count is non-negative by definition, so schema.json's countField (minimum: 0) rejects it (SPEC.md 11.3, 14.3)",
};

// Negative vectors whose root manifest is intentionally not parseable JSON at
// all, so ajv is never reached: encoding/json (and every RFC 8259-conformant
// parser) refuses the bytes before any schema or application check runs. The
// reason names the SPEC.md rule the vector still pins even though the schema
// cannot be the layer that rejects it.
const EXPECT_JSON_SYNTAX_INVALID = {
  "leading-zero-count": "declaredRecordCount is the byte sequence 01; RFC 8259 section 6's int production is `zero / (digit1-9 *DIGIT)`, so a leading zero before another digit is not a legal number token and every conformant JSON parser rejects the manifest at decode time, before the canonical-numeric-form check in SPEC.md 11.3 ever runs (SPEC.md 11.3, 14.3)",
};

// Negative RUNLOG vectors with a deliberately hand-assembled entry the schema
// can and must reject, keyed "<vector>:<1-based line>".
const EXPECT_RUNLOG_LINE_INVALID = {
  "runlog-duplicate-index:3": "synthetic non-ULID placeholder runId 01DUPL1CATE... (SPEC.md 11.6); a hand-assembled duplicate-index entry (SPEC.md 10 anomaly 1, 14.3)",
};

// Which vectors may legitimately yield no root manifest, no RUNLOG, or a run
// directory without one, and which corpus entries are not vectors at all.
// Declared here with a cause, rather than inferred from the tree, so an
// undeclared empty vector refuses (could-not-check) instead of silently
// reading the same as a vector that passed, and a declaration the corpus no
// longer bears out is a finding rather than a silence that is never revisited.
const EXPECT_NO_ROOT_MANIFEST = {
  "crypto-kat": {
    cause: "absent: there is no archive/run",
    why: "a known-answer vector holding only kat.json (master, cak, fileKey, keyCommitment, streamBody), with no archive/ directory (SPEC.md 14, corpus README `Deterministic known-answer`)",
  },
  "kem-combiner-kat": {
    cause: "absent: there is no archive/run",
    why: "a known-answer vector holding only kat.json (ssM, ssX, ctX, pkX, output), with no archive/ directory (SPEC.md 14, corpus README `Deterministic known-answer`)",
  },
  "mldsa-kat": {
    cause: "absent: there is no archive/run",
    why: "a known-answer vector holding only kat.json (publicKey, message, signature), with no archive/ directory (SPEC.md 14, corpus README `Deterministic known-answer`)",
  },
  "mlkem-kat": {
    cause: "absent: there is no archive/run",
    why: "a known-answer vector holding only kat.json (seed, encapKey, cipherText, sharedSecret), with no archive/ directory (SPEC.md 14, corpus README `Deterministic known-answer`)",
  },
};

const EXPECT_NO_RUNLOG = {
  "absent-runlog": {
    cause: "absent: there is no archive/_RECOVERY/RUNLOG, and RUNLOG.sig is there beside it",
    why: "the negative vector whose defect is the missing _RECOVERY/RUNLOG: the generator deletes it and expects mode negative, ExitStale, phase open, leaving RUNLOG.sig beside the absent log (SPEC.md 14.3)",
  },
  "crypto-kat": {
    cause: "absent: there is no archive/_RECOVERY/RUNLOG, and there is no archive/_RECOVERY at all",
    why: "a known-answer vector with no archive/ directory (SPEC.md 14, corpus README `Deterministic known-answer`)",
  },
  "kem-combiner-kat": {
    cause: "absent: there is no archive/_RECOVERY/RUNLOG, and there is no archive/_RECOVERY at all",
    why: "a known-answer vector with no archive/ directory (SPEC.md 14, corpus README `Deterministic known-answer`)",
  },
  "mldsa-kat": {
    cause: "absent: there is no archive/_RECOVERY/RUNLOG, and there is no archive/_RECOVERY at all",
    why: "a known-answer vector with no archive/ directory (SPEC.md 14, corpus README `Deterministic known-answer`)",
  },
  "mlkem-kat": {
    cause: "absent: there is no archive/_RECOVERY/RUNLOG, and there is no archive/_RECOVERY at all",
    why: "a known-answer vector with no archive/ directory (SPEC.md 14, corpus README `Deterministic known-answer`)",
  },
};

// Run directories that hold no root manifest, keyed "<vector>/<runId>". Empty
// today: every run directory in the corpus yields a manifest, so this table
// has no live entry until a vector deliberately pins that.
const EXPECT_RUN_WITHOUT_ROOT_MANIFEST = {};

// Entries beside the vector directories that are not vectors themselves.
const NOT_A_VECTOR = {
  "README.md": {
    cause: "a file",
    why: "the corpus README documenting the vector layout, the expect.json grammar and the regeneration command",
  },
};

function rel(p) {
  return path.relative(REPO_ROOT, p);
}

const realTree = {
  listDir(dir) {
    try {
      return fs.readdirSync(dir);
    } catch {
      return null;
    }
  },
  isDirectory(p) {
    try {
      return fs.statSync(p).isDirectory();
    } catch {
      return false;
    }
  },
  isFile(p) {
    try {
      return fs.statSync(p).isFile();
    } catch {
      return false;
    }
  },
};

// Walks internal/format/testdata/vectors/ and reports, per vector, whether it
// yields a root manifest and a RUNLOG, and why not when it doesn't.
function surveyVectors(tree) {
  const names = tree.listDir(VECTORS_DIR);
  if (names === null) return null;
  const vectors = [];
  const notDirectories = [];
  for (const name of [...names].sort()) {
    const vecDir = path.join(VECTORS_DIR, name);
    if (!tree.isDirectory(vecDir)) {
      notDirectories.push({ name, cause: tree.isFile(vecDir) ? "a file" : "there, and neither a file nor a directory" });
      continue;
    }
    const runDir = path.join(vecDir, "archive", "run");
    const manifests = [];
    const runsWithoutManifest = [];
    let runDirState;
    const runIds = tree.isDirectory(runDir) ? tree.listDir(runDir) : null;
    if (runIds !== null) {
      runDirState = "directory";
      for (const runId of [...runIds].sort()) {
        const file = path.join(runDir, runId, "root.manifest.json");
        if (tree.isFile(file)) manifests.push({ vector: name, runId, file });
        else
          runsWithoutManifest.push({
            vector: name,
            runId,
            why: tree.isDirectory(path.join(runDir, runId))
              ? "the run directory is there and holds no root.manifest.json"
              : "run/" + runId + " is not a directory, so it holds nothing at all",
          });
      }
    } else {
      runDirState = tree.isFile(runDir)
        ? "not a directory: archive/run is a file"
        : tree.isDirectory(runDir)
          ? "a directory that could not be listed"
          : "absent: there is no archive/run";
    }
    const runlogPath = path.join(vecDir, "archive", "_RECOVERY", "RUNLOG");
    const hasRunlog = tree.isFile(runlogPath);
    const runlogState = hasRunlog
      ? "present"
      : tree.isDirectory(runlogPath)
        ? "not a file: _RECOVERY/RUNLOG is a directory"
        : "absent: there is no archive/_RECOVERY/RUNLOG";
    const runlogSibling = tree.isFile(runlogPath + ".sig")
      ? "RUNLOG.sig is there beside it"
      : tree.isDirectory(path.dirname(runlogPath))
        ? "_RECOVERY is there and holds no RUNLOG.sig"
        : "there is no archive/_RECOVERY at all";
    vectors.push({
      vector: name,
      runDirState,
      manifests,
      runsWithoutManifest,
      runlog: hasRunlog ? runlogPath : null,
      runlogState,
      manifestCause: runDirState,
      runlogCause: runlogState + ", and " + runlogSibling,
    });
  }
  return { entries: names.length, vectors, notDirectories };
}

// Decides, over a survey and the declaration tables above, which silences in
// the corpus were declared and still hold, which were declared and no longer
// hold (a finding), and which are undeclared (a refusal: could-not-check).
function auditVectorCoverage(survey, tables) {
  const refusals = [];
  const findings = [];
  const declaredEmptyManifests = [];
  const declaredEmptyRunlogs = [];
  const usedNoManifest = new Set();
  const usedNoRunlog = new Set();
  const usedRunWithout = new Set();
  const usedNotAVector = new Set();

  const filed = survey.vectors.length + survey.notDirectories.length;
  if (filed !== survey.entries) {
    refusals.push(
      "the vectors directory holds " + survey.entries + " entry/entries and the survey filed " + filed + ". " +
        (survey.entries - filed) + " reached no bucket, so this check cannot say what it saw for them"
    );
  }

  const causeHolds = (table, key, observed, site) => {
    const decl = table[key];
    if (typeof decl?.cause !== "string" || decl.cause.length === 0) {
      refusals.push(site + " declares " + JSON.stringify(key) + " and names no cause, so nothing can say whether the silence it permits is still the silence that was granted");
      return;
    }
    if (decl.cause !== observed) {
      findings.push(
        site + " declares " + JSON.stringify(key) + " because " + JSON.stringify(decl.cause) + ", and it is now " +
          JSON.stringify(observed) + ". The silence is still there and its cause is not, so the exemption is being applied to something it was not granted for"
      );
    }
  };

  for (const entry of survey.notDirectories) {
    if (Object.prototype.hasOwnProperty.call(tables.notAVector, entry.name)) {
      usedNotAVector.add(entry.name);
      causeHolds(tables.notAVector, entry.name, entry.cause, "NOT_A_VECTOR");
      continue;
    }
    refusals.push(JSON.stringify(entry.name) + " sits beside the vector directories and is not a directory, and it is not declared in NOT_A_VECTOR either");
  }

  let yieldsManifest = 0;
  let yieldsRunlog = 0;
  let undeclaredEmptyManifests = 0;
  let undeclaredEmptyRunlogs = 0;
  for (const v of survey.vectors) {
    if (v.manifests.length > 0) {
      yieldsManifest += 1;
    } else if (Object.prototype.hasOwnProperty.call(tables.noRootManifest, v.vector)) {
      usedNoManifest.add(v.vector);
      declaredEmptyManifests.push(v.vector);
      causeHolds(tables.noRootManifest, v.vector, v.manifestCause, "EXPECT_NO_ROOT_MANIFEST");
    } else {
      undeclaredEmptyManifests += 1;
      refusals.push("vector " + JSON.stringify(v.vector) + " yields no root manifest (" + v.runDirState + ") and is not declared in EXPECT_NO_ROOT_MANIFEST");
    }

    if (v.runlog !== null) {
      yieldsRunlog += 1;
    } else if (Object.prototype.hasOwnProperty.call(tables.noRunlog, v.vector)) {
      usedNoRunlog.add(v.vector);
      declaredEmptyRunlogs.push(v.vector);
      causeHolds(tables.noRunlog, v.vector, v.runlogCause, "EXPECT_NO_RUNLOG");
    } else {
      undeclaredEmptyRunlogs += 1;
      refusals.push("vector " + JSON.stringify(v.vector) + " yields no RUNLOG (" + v.runlogState + ") and is not declared in EXPECT_NO_RUNLOG");
    }

    for (const r of v.runsWithoutManifest) {
      const key = r.vector + "/" + r.runId;
      if (Object.prototype.hasOwnProperty.call(tables.runWithoutRootManifest, key)) {
        usedRunWithout.add(key);
        causeHolds(tables.runWithoutRootManifest, key, r.why, "EXPECT_RUN_WITHOUT_ROOT_MANIFEST");
        continue;
      }
      refusals.push("run directory " + JSON.stringify(key) + " yields no root manifest (" + r.why + ") and is not declared in EXPECT_RUN_WITHOUT_ROOT_MANIFEST");
    }
  }

  const manifestAxis = yieldsManifest + declaredEmptyManifests.length + undeclaredEmptyManifests;
  const runlogAxis = yieldsRunlog + declaredEmptyRunlogs.length + undeclaredEmptyRunlogs;
  if (manifestAxis !== survey.vectors.length) {
    refusals.push("the manifest axis accounted for " + manifestAxis + " of " + survey.vectors.length + " vector(s)");
  }
  if (runlogAxis !== survey.vectors.length) {
    refusals.push("the RUNLOG axis accounted for " + runlogAxis + " of " + survey.vectors.length + " vector(s)");
  }

  const present = new Map(survey.vectors.map((v) => [v.vector, v]));
  for (const name of Object.keys(tables.noRootManifest)) {
    if (usedNoManifest.has(name)) continue;
    findings.push("EXPECT_NO_ROOT_MANIFEST declares " + JSON.stringify(name) + " yields no root manifest, and " + (present.has(name) ? "it yields " + present.get(name).manifests.length : "there is no such vector directory"));
  }
  for (const name of Object.keys(tables.noRunlog)) {
    if (usedNoRunlog.has(name)) continue;
    findings.push("EXPECT_NO_RUNLOG declares " + JSON.stringify(name) + " yields no RUNLOG, and " + (present.has(name) ? "it has one at " + rel(present.get(name).runlog) : "there is no such vector directory"));
  }
  for (const key of Object.keys(tables.runWithoutRootManifest)) {
    if (usedRunWithout.has(key)) continue;
    findings.push("EXPECT_RUN_WITHOUT_ROOT_MANIFEST declares " + JSON.stringify(key) + ", and no such run directory came back empty");
  }
  for (const name of Object.keys(tables.notAVector)) {
    if (usedNotAVector.has(name)) continue;
    findings.push("NOT_A_VECTOR declares " + JSON.stringify(name) + ", and it is " + (present.has(name) ? "a vector directory" : "not there at all"));
  }

  return { refusals, findings, declaredEmptyManifests, declaredEmptyRunlogs, yieldsManifest, yieldsRunlog };
}

const DECLARED_EMPTY = {
  noRootManifest: EXPECT_NO_ROOT_MANIFEST,
  noRunlog: EXPECT_NO_RUNLOG,
  runWithoutRootManifest: EXPECT_RUN_WITHOUT_ROOT_MANIFEST,
  notAVector: NOT_A_VECTOR,
};

// The only place the audit turns into an exit code. Runs before a single
// manifest is validated: a run that is going to refuse should refuse before
// it prints a hundred `ok` lines that invite the reader to stop there.
function requireDeclaredCoverage(survey) {
  const audit = auditVectorCoverage(survey, DECLARED_EMPTY);

  if (audit.refusals.length > 0) {
    console.error("REFUSED: " + audit.refusals.length + " part(s) of the conformance corpus came back empty");
    console.error("  and nothing in this file says they are allowed to.");
    for (const r of audit.refusals) console.error("    " + r);
    console.error("\n  REMEDY: if the corpus is incomplete, restore it with");
    console.error("  `go test ./internal/format -run TestConformance -update`. If a vector is meant to yield");
    console.error("  nothing, declare it in EXPECT_NO_ROOT_MANIFEST, EXPECT_NO_RUNLOG or");
    console.error("  EXPECT_RUN_WITHOUT_ROOT_MANIFEST with the reason and the SPEC.md rule.");
    process.exit(2);
  }

  if (audit.findings.length > 0) {
    console.error("FAIL: " + audit.findings.length + " declaration(s) in this file no longer describe the corpus:");
    for (const f of audit.findings) console.error("  - " + f);
    console.error("\n  REMEDY: delete the line. These tables exist to name the silences that are intended.");
    process.exit(1);
  }

  console.log(
    "corpus surveyed: " + survey.vectors.length + " vector(s) and " + survey.notDirectories.length +
      " declared non-vector entry/entries account for all " + survey.entries + " entries under " + rel(VECTORS_DIR) + ". " +
      audit.yieldsManifest + " yield a root manifest and " + audit.yieldsRunlog + " a RUNLOG; the rest are declared empty."
  );
  return audit;
}

function main() {
  // The schema is JSON Schema draft 2020-12, so use ajv's 2020 build (the default
  // ajv export only knows draft-07 and rejects the 2020-12 $schema meta).
  const ajvModule = requireHere(AJV_MODULE);
  const Ajv = ajvModule.default ?? ajvModule;

  // strict: true everywhere, except strictRequired: the ShardRecord if/then
  // requires recordSalt (defined in the parent properties) from inside a
  // conditional applicator, which strictRequired flags even though the property
  // is defined. This is the intended secrets-only modelling of SPEC.md 6.3, so
  // the one sub-check is relaxed while strict schema validation otherwise holds.
  const ajv = new Ajv({ allErrors: true, strict: true, strictRequired: false });
  const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf8"));

  let validateTop;
  try {
    validateTop = ajv.compile(schema);
  } catch (err) {
    console.error("SCHEMA NOT WELL-FORMED: " + err.message);
    process.exit(1);
  }
  void validateTop;
  console.log("schema well-formed: docs/format/schema.json compiled");

  // The named subschemas, addressed by $ref, so a manifest is checked against
  // exactly RootManifest and a RUNLOG line against exactly RunlogEntry rather
  // than the permissive top-level oneOf.
  const validateRoot = ajv.getSchema(schema.$id + "#/$defs/RootManifest");
  const validateRunlog = ajv.getSchema(schema.$id + "#/$defs/RunlogEntry");
  if (!validateRoot || !validateRunlog) {
    console.error("SCHEMA MISSING a required $def (RootManifest / RunlogEntry)");
    process.exit(1);
  }

  // The corpus is surveyed before it is validated, and the survey is refused
  // before a vector is read: an undeclared empty vector is a could-not-check.
  const survey = surveyVectors(realTree);
  if (survey === null) {
    console.error("REFUSED: " + VECTORS_DIR + " could not be listed, so no vector was surveyed.");
    process.exit(2);
  }
  requireDeclaredCoverage(survey);

  const manifestsToCheck = survey.vectors.flatMap((v) => v.manifests).sort((a, b) => a.file.localeCompare(b.file));
  const runlogsToCheck = survey.vectors
    .filter((v) => v.runlog !== null)
    .map((v) => ({ vector: v.vector, file: v.runlog }))
    .sort((a, b) => a.file.localeCompare(b.file));

  let validated = 0;
  let expectedFailures = 0;
  const failures = [];

  for (const { vector, file } of manifestsToCheck) {
    const expectSyntaxInvalid = Object.prototype.hasOwnProperty.call(EXPECT_JSON_SYNTAX_INVALID, vector);
    let data;
    try {
      data = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (err) {
      if (expectSyntaxInvalid) {
        expectedFailures += 1;
        console.log("ok (rejected as designed, not valid JSON syntax): " + rel(file) + " [" + EXPECT_JSON_SYNTAX_INVALID[vector] + "]");
      } else {
        failures.push(rel(file) + ": not parseable JSON: " + err.message);
      }
      continue;
    }
    if (expectSyntaxInvalid) {
      failures.push(rel(file) + ": expected to fail JSON.parse (" + EXPECT_JSON_SYNTAX_INVALID[vector] + ") but it parsed as valid JSON.");
      continue;
    }
    const ok = validateRoot(data);
    const expectInvalid = Object.prototype.hasOwnProperty.call(EXPECT_SCHEMA_INVALID, vector);

    if (expectInvalid) {
      if (ok) {
        failures.push(rel(file) + ": expected to fail the schema (" + EXPECT_SCHEMA_INVALID[vector] + ") but it validated. The schema is too permissive.");
      } else {
        expectedFailures += 1;
        console.log("ok (rejected as designed): " + rel(file) + " [" + EXPECT_SCHEMA_INVALID[vector] + "]");
      }
      continue;
    }

    if (!ok) {
      failures.push(rel(file) + ": real/valid manifest FAILED the schema:\n  " + ajv.errorsText(validateRoot.errors, { separator: "\n  " }));
    } else {
      validated += 1;
      console.log("ok: " + rel(file));
    }
  }

  for (const { vector, file } of runlogsToCheck) {
    const rawLines = fs.readFileSync(file, "utf8").split("\n");
    let lineNo = 0;
    for (const raw of rawLines) {
      lineNo += 1;
      if (raw.length === 0) {
        if (lineNo === rawLines.length) continue; // the terminating newline, not a line
        failures.push(rel(file) + " line " + lineNo + ": blank line in a RUNLOG. SPEC.md 10 defines the RUNLOG as one JSON object per line.");
        continue;
      }
      const key = vector + ":" + lineNo;
      const expectInvalid = Object.prototype.hasOwnProperty.call(EXPECT_RUNLOG_LINE_INVALID, key);
      let entry;
      try {
        entry = JSON.parse(raw);
      } catch (err) {
        failures.push(rel(file) + " line " + lineNo + ": not parseable JSON: " + err.message);
        continue;
      }
      const ok = validateRunlog(entry);
      if (expectInvalid) {
        if (ok) {
          failures.push(rel(file) + " line " + lineNo + ": expected to fail the schema (" + EXPECT_RUNLOG_LINE_INVALID[key] + ") but it validated.");
        } else {
          expectedFailures += 1;
          console.log("ok (rejected as designed): " + rel(file) + " line " + lineNo + " [" + EXPECT_RUNLOG_LINE_INVALID[key] + "]");
        }
        continue;
      }
      if (!ok) {
        failures.push(rel(file) + " line " + lineNo + ": RUNLOG entry FAILED the schema:\n  " + ajv.errorsText(validateRunlog.errors, { separator: "\n  " }));
      } else {
        validated += 1;
        console.log("ok: " + rel(file) + " line " + lineNo);
      }
    }
  }

  console.log("");
  console.log("validated " + validated + " structurally valid manifest/RUNLOG objects; " + expectedFailures + " negative vectors rejected as designed");

  if (failures.length > 0) {
    console.error("");
    console.error("FAIL: " + failures.length + " problem(s):");
    for (const f of failures) console.error("  - " + f);
    process.exit(1);
  }
  console.log("PASS");
}

main();
