#!/usr/bin/env node
// Validates the on-disk downpipe/0.1.0 conformance vector manifests against
// docs/format/schema.json using ajv (SPEC.md section 14). NEVER edits a vector
// or weakens SPEC.md: the schema describes the frozen downpipe/0.1.0 wire format,
// and this checker confirms every structurally valid manifest matches it while
// the deliberately malformed negative vectors are rejected exactly where SPEC.md
// says a reader rejects them.
//
// Scope. The schema can validate only the CLEARTEXT JSON the format exposes on
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
// does not express, MUST pass the schema.
//
// A smaller set of negative vectors mutate the manifest into bytes that are not
// valid JSON at all (RFC 8259 syntax, not a schema shape), so ajv is never
// reached: encoding/json, and every conformant parser, refuses to decode them
// before any schema or application check runs. Those are listed in
// EXPECT_JSON_SYNTAX_INVALID and asserted to fail JSON.parse rather than being
// treated as an unparseable-manifest bug in the vector.

// ESM rather than CommonJS, and the reason is the guard import two lines down: the shared completion
// guard is an ES module, and requiring one from CommonJS depends on the running node being 22.12 or
// later. The file is .mjs so it is an ES module whatever the package's `type` says, which leaves the
// nested package.json and its lockfile untouched.
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
// Importing this ARMS the completion guard: reaching exit without declaring a verdict forces a
// non-zero exit, so a run that stopped before its tally cannot report success.
import { verdictReached, verdictSkipped } from "../lib/verdict-guard.mjs";
// And this READS the load recorder, which `--import ./arm-load-recorder.mjs` armed before this file was
// fetched. Importing it here does not arm anything: by the time this line is reached the preload has
// already evaluated, so this resolves to the same module instance and merely borrows its record.
import { loadRecord, recorderArmed } from "./arm-load-recorder.mjs";

// ajv is NOT imported at the top of the file, and the reason is the pin check below rather than load
// time. A static `import Ajv from "ajv/dist/2020.js"` is hoisted above every line here, so on a checkout
// where nobody has installed anything it throws ERR_MODULE_NOT_FOUND before requirePinnedValidator can
// say so, and the completion guard then fires over the top of it with a message about a verdict that was
// never reached. That is a could-not-check wearing a failure's costume, which is exactly the shape this
// file's own guard exists to stop. Resolving ajv after the pin check has been made keeps the order
// honest: say what the lockfile requires, then load it.
const requireHere = createRequire(import.meta.url);

// THE LOAD RECORDER IS NOT ARMED HERE, AND THAT IS THE POINT. The census in main() used to ask
// `requireHere.cache` what this process had loaded, and a cache is a MUTABLE END STATE: it answers for
// what is still in it at the moment it is asked, not for what ran.
//
// THREE BYPASSES, ALL DRIVEN with exit codes read off the process, not through a pipe. The
// baseline for every run is the census working: prepend to node_modules/fast-uri/index.js one `require`
// of a path climbing out to this repository's scripts/ directory and the run is EXIT 1 naming that file.
// Then, on the same tree:
//
//   ONE LINE MORE. Let the file that ran end with `delete require.cache[__filename]`. The run is EXIT 0
//   at 112 checks, the census prints "all 88 CommonJS module(s)", which is the same 88 a clean tree
//   prints, and the foreign file has written a marker naming this process's own pid. The evidence
//   removed itself.
//
//   A DIFFERENT MODULE SYSTEM. Replace the `require` with `import()` of an .mjs. EXIT 0 at 112 checks,
//   the same 88 again, marker written. An ES module never enters require.cache at all, so the census
//   was never looking in the place that code arrives through.
//
//   AND AN EARLIER MOMENT, which is what an arming statement in this body could never reach. Add
//   `import "../foreign-preload.mjs";` to ../lib/verdict-guard.mjs, which this file statically imports.
//   A static import is evaluated before the importing module's body runs, so the guard and its whole
//   import graph loaded while the recorder was still disarmed: EXIT 0, VERDICT PASS at 112 checks, the
//   same 88, marker written. A pre-arming CommonJS load is still caught, by censusPopulation's refusal
//   when the cache holds a key the recorder never saw; a pre-arming ES load is in neither half of the
//   union, so it is invisible rather than merely unrecorded.
//
// TWO OBVIOUS REMEDIES WERE MEASURED AND NEITHER IS AVAILABLE. Making the cache tamper-proof is the first
// thing to reach for and `Object.freeze(requireHere.cache)` before ajv loads throws "Cannot add
// property .../ajv/dist/2020.js, object is not extensible": the frozen cache cannot hold the module the
// census exists to describe, so the run has no validator. Every softer variant of the same idea, a proxy
// with a deleteProperty trap among them, is CommonJS BY CONSTRUCTION and leaves the second bypass exactly
// where it is. Moving the arming statement to the first line of this body is the second, and it closes
// the one import this file has today while leaving the next one open. Both are a fix narrower than their
// own hole, which is the shape this file has now bought twice and does not intend to buy again.
//
// SO THE ARMING HAPPENS BEFORE THIS FILE IS FETCHED. `./arm-load-recorder.mjs` is loaded through node's
// `--import` flag, which fully evaluates a module before the entry point is resolved, so there is no
// arming line for a later import to be added above. `module.registerHooks` is synchronous and its load
// hook fires for BOTH module systems, so each load is filed before the loaded code gets to run and delete
// anything. The census in main() then reads the UNION of what was recorded and what the cache still
// holds: a deletion cannot shrink a union, and an ES module is in it because the recorder saw it even
// though the cache never will. See censusPopulation for the recorder's own positive control.
//
// AND THE FLAG IS NOT TAKEN ON TRUST. Because the preload arms before the entry point is fetched, THIS
// FILE'S OWN LOAD is in the record. entryObservedVerdict requires it to be, so a run that lost the flag
// refuses at exit 2 naming it rather than censusing a population that begins wherever arming happened to
// start. See REPO_OWN_LOADS for why that makes this file and the guard permitted rather than foreign.

const SELF_DIR = path.dirname(fileURLToPath(import.meta.url));
const LOCK_PATH = path.join(SELF_DIR, "package-lock.json");
const INSTALL_RECORD = path.join(SELF_DIR, "node_modules", ".package-lock.json");
const REPO_ROOT = path.resolve(SELF_DIR, "..", "..");
const SCHEMA_PATH = path.join(REPO_ROOT, "docs", "format", "schema.json");
const VECTORS_DIR = path.join(REPO_ROOT, "internal", "format", "testdata", "vectors");

// THE REPOSITORY'S OWN FILES THIS ENTRY POINT RUNS, NAMED ONE BY ONE. Arming before the entry point is
// fetched makes this file, the preload and the shared guard visible to the census for the first time, and
// none of them sits inside a package the lockfile pins. Left unaddressed they are three findings on a
// clean tree, so the census needs to be told which of the repository's own files this gate legitimately
// executes.
//
// A LIST AND NOT A DIRECTORY, and the difference is the whole check. Grading `scripts/` would make the
// planted file that drove this change LEGITIMATE rather than visible, because that file sits under
// `scripts/` too, and it would simultaneously reopen the two bypasses closed the day before, whose whole
// shape is a file under `scripts/` executed from inside node_modules. MEASURED, exit code
// read off the process: a foreign CommonJS file planted at scripts/lib/ and required after arming is EXIT
// 1 naming it, which is exactly the finding a graded `scripts/lib` would have thrown away. A directory
// permission is also a standing one: every file later added under it loads unremarked.
//
// EACH PATH MUST EXIST, checked below rather than assumed, because a list naming a file that is not there
// permits nothing and would go on permitting nothing in silence.
//
// THE PRELOAD IS ON THE LIST THOUGH IT IS NOT EXPECTED IN THE RECORD. It is evaluated before it arms
// itself, so it files no entry for its own load, and this file's static import of it resolves to the
// module already in the registry rather than fetching it again. It is named anyway: a run that reached it
// by some other route must be permitted on the same terms as the rest, not refused for an accident of
// ordering.
const REPO_OWN_LOADS = [
  path.join(SELF_DIR, "validate.mjs"),
  path.join(SELF_DIR, "arm-load-recorder.mjs"),
  path.resolve(SELF_DIR, "..", "lib", "verdict-guard.mjs"),
];

// Negative vectors whose root manifest is INTENTIONALLY a shape the schema can
// express and therefore must reject. The reason names the SPEC.md rule.
const EXPECT_SCHEMA_INVALID = {
  "unknown-major": "formatVersion is downpipe/9.0.0, not the const downpipe/0.1.0 (SPEC.md 13, 14.3)",
  "unimplemented-minor": "formatVersion is downpipe/0.2.0, not the const downpipe/0.1.0 (SPEC.md 13, 14.3)",
  "unknown-codec": "envelope.codec is zstd, outside the closed {none, gzip} enum (SPEC.md 5.2, 14.3)",
  "count-over-2pow53": "declaredRecordCount is the JSON number 9007199254740993, above 2^53-1 (SPEC.md 11.3, 14.3)",
  "missing-break-glass": "breakGlassPresent is false and no break-glass recipient is present (SPEC.md 5.2, 14.3)",
  "negative-count": "declaredRecordCount is the JSON number -1; a count is non-negative by definition, so schema.json's countField (minimum: 0) rejects it (SPEC.md 11.3, 14.3)",
};

// Negative vectors whose root manifest is INTENTIONALLY not parseable JSON at
// all, so ajv is never reached: encoding/json (and every RFC 8259-conformant
// parser) refuses the bytes before any schema or application check runs. The
// reason names the SPEC.md rule the vector still pins even though the schema
// cannot be the layer that rejects it.
const EXPECT_JSON_SYNTAX_INVALID = {
  "leading-zero-count": "declaredRecordCount is the byte sequence 01; RFC 8259 section 6's int production is `zero / (digit1-9 *DIGIT)`, so a leading zero before another digit is not a legal number token and every conformant JSON parser rejects the manifest at decode time, before the canonical-numeric-form check in SPEC.md 11.3 ever runs (SPEC.md 11.3, 14.3)",
};

// Negative RUNLOG vectors with a deliberately hand-assembled entry the schema can
// and must reject, keyed by "<vector>:<1-based line>". runlog-duplicate-index line
// 3 carries the synthetic placeholder runId 01DUPL1CATE..., which is not a
// canonical Crockford base32 ULID (L is excluded, SPEC.md 11.6); the duplicate
// index is the corruption the vector exercises (SPEC.md 10 anomaly 1, 14.3).
const EXPECT_RUNLOG_LINE_INVALID = {
  "runlog-duplicate-index:3": "synthetic non-ULID placeholder runId 01DUPL1CATE... (SPEC.md 11.6); a hand-assembled duplicate-index entry (SPEC.md 10, 14.3)",
};

// WHICH VECTORS MAY LEGITIMATELY YIELD NOTHING, declared here because the code below reads these
// tables rather than reasoning about the corpus.
//
// THE GAP THEY CLOSE. The two listers used to walk the corpus and keep what they found: a vector with
// no `archive/run` directory was passed over, a run directory holding no `root.manifest.json` was
// passed over, and a vector with no `_RECOVERY/RUNLOG` was passed over. None of the three said so.
// MEASURED against the real corpus, exit code read off the process: renaming
// `master-capsule/archive/run` out of the way is EXIT 0, VERDICT PASS, with the checks falling from
// 112 to 111 and no line anywhere in the output naming master-capsule. A vector that went ungraded and
// a vector that passed read the same, which is the definition of a could-not-check wearing a pass.
//
// WHY A DECLARED LIST WITH A REASON, and not the two alternatives.
//
// A COUNT FLOOR was the obvious cheap answer and it is insufficient, driven rather than argued. A floor
// asserting 112 objects passes a SWAP by construction:, removing `seg-empty/archive/run`
// and adding a second run directory under master-capsule holding a copy of its own manifest leaves the
// count at exactly 112, so a floor of 112 is satisfied while one vector of the frozen corpus was never
// put through the schema at all. A count cannot distinguish 112 objects from the right 112 objects.
//
// A PER-VECTOR MARKER inside the vector was the better-looking answer and it is the wrong layer here.
// The corpus is regenerated wholesale by `go test ./internal/format -run TestConformance -update`, so a
// marker file would have to be written by the Go generator, and the four vectors that need one are
// precisely the four that are not archives and have no `expect.json` to carry a field. A declaration in
// the checker needs no change to the frozen corpus and is read by the thing that enforces it.
//
// THE THREE TABLES MIRROR THE THREE PLACES A VECTOR CAN COME BACK EMPTY, so a declaration says which
// silence is permitted rather than blanket-exempting a name. A vector absent from all three and empty
// anywhere REFUSES at exit 2 naming the vector: could-not-check is what that is. A declaration the
// corpus no longer bears out is a FINDING at exit 1, because a list nobody prunes is where names go to
// be parked, and the tree is then known to disagree with this file rather than merely unread.

// Vectors that yield no root manifest at all. All four are known-answer test vectors: each holds one
// file, `kat.json`, and no `archive/` directory whatever, because they pin a cryptographic primitive
// against a fixed input rather than an archive a reader opens. They are graded by the Go tests in
// internal/format, and there is no cleartext manifest here for a schema to have an opinion about.
//
// THE REASON IS READ OFF THE GENERATOR RATHER THAN INFERRED FROM THE TREE, which is the difference
// between knowing a vector is meant to be empty and observing that it is. These four are exactly the
// members of `katDirs` at internal/format/conformance_test.go:401, the set the corpus regenerator
// exempts from its own wholesale delete at conformance_test.go:438 alongside README.md, and they are
// built by generateCryptoKAT, generateMLKEMKAT, generateMLDSAKAT and generateCombinerKAT rather than by
// generateVector, which is the function that writes an `archive/` at all. The corpus README lists the
// same four under "Deterministic known-answer".
//
// AND THE CAUSE IS DECLARED BESIDE THE REASON, which is the third direction this ledger was open in.
// A declaration used to be checked two ways: a NEW undeclared empty refuses, and a declaration the
// corpus no longer bears out is a finding. Neither of those sees the case where the vector is STILL
// empty and the thing that made it empty has changed underneath the declaration. crypto-kat growing an
// empty `archive/run` directory yields no root manifest exactly as before, so the declaration goes on
// being satisfied while the reason it gives, no archive/ directory at all, has stopped being true. The
// exemption was granted for one cause and would silently keep applying to another.
//
// `cause` IS THE STATE THE SURVEY MUST REPORT, string for string, not prose about it. It is checked
// against surveyVectors' own field rather than against a re-reading of the tree, so the comparison
// cannot drift from what the refusal messages print. A declaration carrying no `cause` REFUSES: an
// exemption that names no cause cannot be held to one.
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

// Vectors that yield no RUNLOG. The four known-answer vectors again, for the same reason: no archive.
//
// AND ONE THAT IS A DIFFERENT KIND OF EMPTY, which is the whole reason these are two tables and not
// one. absent-runlog HAS an archive, its root manifest IS validated below, and the file this lister
// looks for is missing BECAUSE THAT IS THE DEFECT THE VECTOR PINS. Read off the generator rather than
// off the tree: internal/format/conformance_vectors_test.go:552 defines it with the tamper
// `removeFile(dir/archive/_RECOVERY/RUNLOG)` and the expectation
// { Mode: "negative", ExitCode: ExitStale, Phase: "open" }, so the file is deleted on purpose after the
// archive is built and a conformant reader must refuse to open the run. Its `_RECOVERY/RUNLOG.sig` is
// left in place beside the hole, which is what a reader sees. A vector empty because it is a negative
// case and a vector empty because a directory went missing are indistinguishable from the outside, and
// this table is the thing that says which one is which.
//
// AND THIS IS THE TABLE WHERE THE THIRD DIRECTION BITES HARDEST, because these five vectors are empty
// on one axis in the same state for two opposite reasons. absent-runlog's declared cause names the
// signature left beside the hole, which is what makes it the negative vector rather than a broken one;
// the four known-answer vectors have no _RECOVERY at all. Checked against "absent" alone the two are
// the same string, so absent-runlog's whole archive could go missing and its declaration would go on
// being satisfied for a reason it does not give.
const EXPECT_NO_RUNLOG = {
  "absent-runlog": {
    cause: "absent: there is no archive/_RECOVERY/RUNLOG, and RUNLOG.sig is there beside it",
    why: "the negative vector whose defect IS the missing _RECOVERY/RUNLOG: the generator deletes it (conformance_vectors_test.go:552, tamper removeFile) and expects mode negative, ExitStale, phase open, leaving RUNLOG.sig beside the absent log (SPEC.md 14.3)",
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

// Run directories that hold no root manifest, keyed "<vector>/<runId>" as the RUNLOG table is keyed
// "<vector>:<line>".
//
// EMPTY, AND THAT IS THE POINT. Measured: 56 run directories on disk and 56 root
// manifests, so every run directory yields one and this site has NO live instance. That made it the
// most dangerous of the three rather than the safest, because nothing in the corpus exercised it and
// nothing in the output would have named it. The corpus README states the layout as
// `run/<runId>/root.manifest.json`, so a run directory without one is a run a reader cannot open, and
// this table stays empty until a vector deliberately pins that.
const EXPECT_RUN_WITHOUT_ROOT_MANIFEST = {};

// Entries beside the vector directories that are not vectors. The corpus README documents the layout
// and is the only one. It is DECLARED rather than pattern-matched, so a second file appearing here is
// refused by name instead of being filtered out by a rule wide enough to admit it.
const NOT_A_VECTOR = {
  "README.md": {
    cause: "a file",
    why: "the corpus README documenting the vector layout, the expect.json grammar and the regeneration command",
  },
};

// THREE CONSTANTS WHERE THERE USED TO BE ONE, and the split is the whole of the repair below rather
// than tidying. `node_modules/` was serving as the path separator, as the marker of an install
// location, and as the prefix to slice off a name, and a single string cannot answer three questions.
// A key is a path, so the separator is a separator and the directory name is a directory name.
const SEP = "/";
const NM_SEG = "node_modules";
const NM = NM_SEG + SEP;

// THE JUDGE, NAMED, because everything below is a claim about docs/format/schema.json and ajv is what
// makes it. A run that compared four packages and not this one graded the frozen downpipe/0.1.0 vectors
// under an unpinned validator, and the count of packages compared cannot tell anybody that: it is the
// same number whether the fifth was ajv or fast-deep-equal. AJV_MODULE is the specifier main() actually
// loads, and selfTest asserts JUDGE is its package, so the floor cannot drift away from the require.
const AJV_MODULE = "ajv/dist/2020.js";
const JUDGE = "ajv";

// The `packages` key grammar this file models is lockfileVersion 2 and 3. See requireLockfileShape.
const MODELLED_LOCKFILE_VERSIONS = [2, 3];

// classifyLockPackages sorts a lockfile's `packages` map into the four dispositions this check has:
// COMPARED, SET ASIDE as a workspace member, EXCLUDED as optional or platform-gated, and REFUSED as
// nested. It is a pure function of the map, taking no filesystem and no process state, so `--self-test`
// drives the real classifier rather than a restatement of its rules. A control that re-implements the
// rule it is checking agrees with itself and with nothing else.
//
// THE LOCKFILE'S OWN ROOT ENTRY is keyed "" and holds this project rather than a dependency. It is the
// one key with nothing to compare, so it is FILED as `root` and counted rather than skipped, which is
// what makes the arithmetic below total: filed + root equals the number of keys the map holds, and that
// denominator is read off the input rather than recomputed with the rule under test.
//
// AND THE ENTRY IS READ RATHER THAN REQUIRED, which is the whole of the fourth generation. See
// readEntry and the block above it.
//
// THREE ASSUMPTIONS ABOUT THIS LOCKFILE, all of which hold today and none of which is left silent,
// because a check that quietly drops entries is one that can pass having compared less than it says.
//
// The first is that nothing here is optional or platform-gated. An entry npm is entitled not to install
// has to be excluded or this fails on every machine, so the exclusion stays, but every excluded name is
// PRINTED on the pass line rather than dropped where nobody sees it.
//
// The second is that the tree is flat. A key of the form node_modules/a/node_modules/b is a nested copy,
// meaning b as resolved from inside a, and resolving it from this file would reach the top-level b
// instead and grade the wrong package. Rather than guess or skip, that REFUSES at exit 2 and says what
// it would need. ajv's closure is four flat packages today, so this arm is a tripwire on a lockfile that
// has grown a shape this check does not model.
//
// THE THIRD WAS UNSTATED AND WAS WRONG: that every versioned key is an install location. It is not.
// lockfileVersion 2 and 3 also emit one key per WORKSPACE MEMBER, keyed by its path in the repository
// rather than by where npm put it, and that key carries a `version` like any other. It names no
// dependency: npm never fetches a workspace member, it LINKS it into node_modules under the member's
// package name, and records that link as a SEPARATE key carrying `link: true` and no version, which the
// version test above already skips. So the only key npm offers for a workspace member is one nothing can
// resolve.
//
// SET ASIDE RATHER THAN REFUSED, and the distinction is the whole three-valued convention rather than a
// preference. Refusing is right for a nested entry because there the check would resolve a DIFFERENT
// package of the same name and could return a false PASS, so it genuinely cannot grade what it was
// given. A workspace key carries no such risk: it names no dependency this file would misresolve, ajv is
// still at node_modules/ajv and is still compared, so refusing would throw away a check that can do the
// whole of its job. Exit 2 is for could-not-check, not for could-check-but-found-something-else.
//
// AND GRADING IT WAS THE WORST OF THE THREE, which is what this file did before. Nothing resolves the
// key `packages/x`, so the probe fails, the member is reported `NOT INSTALLED packages/x` at exit 1, and
// the remedy printed beside it is `npm ci`. MEASURED against a workspace npm itself
// created, with the member's package.json on disk and the link in node_modules exactly as npm intends:
// `npm ci` exits 0, adds all five packages, rewrites nothing, and the finding is byte-identical
// afterwards. An accusation whose printed remedy runs clean and changes nothing is worse than either a
// pass or a refusal, because the reader has no move left that the tool will accept.
//
// THE THIRD GENERATION OF THIS DISCRIMINATOR, and the reason there is a third is that the second was
// called total when it was only exhaustive. Those are different properties and the difference is the
// whole finding. The second generation asked `key.indexOf("node_modules/")` and branched on the answer:
// -1 meant a workspace path, 0 with no second occurrence meant a top-level install, anything else meant
// nested. Every key did land in some bucket, so the self-test's filed === versioned assertion passed,
// and it would have passed for ANY input, because the workspace arm was the DEFAULT arm. Exhaustive by
// having a fall-through is not the same as sound, and a default arm is where the unmodelled keys go to
// be counted as understood.
//
// MEASURED against this directory's real lockfile with the real node_modules installed,
// control first: unmodified, exit 0, VERDICT PASS checks=112, all 5 packages compared. Then four
// mutations, one key each, nothing else touched.
//
//   1. `node_modules\ajv` at version 0.0.0-not-installed          EXIT 0, PASS, 112 checks
//   2. `packages/my-node_modules/lib`, a workspace member         EXIT 2, refused as nested
//   3. `node_modules/@node_modules/foo`, a top-level scoped install  EXIT 2, refused as nested
//   4. `node_modules/ajv/node_modules/fast-uri` marked optional   EXIT 0, excluded, tripwire silent
//
// THE FIRST IS THE ONE THAT MATTERS and it is a FALSE PASS on the single thing this file exists to pin.
// A backslash is not the separator npm writes, so indexOf found nothing, so ajv fell into the default
// arm and was printed as a workspace member set aside. The run reported "all 4 package(s) resolve" and
// passed. A version that cannot exist was never compared, and the reader was told, truthfully as far as
// the sentence goes, that one workspace member had been set aside.
//
// The middle two are the mirror: both are shapes this check can grade perfectly well and both were
// refused at exit 2, which by this file's own convention is for could-not-check and not for
// could-check-but-this-is-not-the-question. `my-node_modules` is a directory whose name merely ENDS IN
// the sentinel, and `@node_modules` is a SCOPE. An offset test cannot tell either from the real thing
// because it is looking for a substring, and a substring match answers none of the three questions
// actually being asked: is this the separator, is this a whole directory name, is this a scope.
//
// The fourth is not an ordering nit. The optional and platform test ran BEFORE the nested test, so a
// nested entry marked optional left as an exclusion and the tripwire never fired: the refusal could be
// switched off by an attribute. It also printed the exclusion as `ajv/node_modules/fast-uri`, having
// sliced only the leading `node_modules/` from a key it had not placed, so it named a package that
// cannot exist as though it were one.
//
// SO THE KEY IS PARSED INTO SEGMENTS RATHER THAN SEARCHED FOR A SUBSTRING. A `packages` key is a POSIX
// relative path, npm writes it with forward slashes on every platform, and every question this function
// has is a question about its segments. `segs.indexOf(NM_SEG)` compares whole segments for equality, so
// `my-node_modules` is not `node_modules`, `@node_modules` is not `node_modules`, and a backslash is not
// a separator. One test, three answers, by construction rather than by cases.
//
// AND THERE IS NO DEFAULT ARM. Each of the four dispositions is now entered on a predicate that was
// checked, and a key matching none of them lands in a FIFTH bucket, `unmodelled`, which refuses. That is
// what makes this rule total in the sense the last one was not: totality is not that every key is filed,
// it is that no key is filed by falling off the end of the tests. `node_modules\ajv` is the case in
// point. Splitting on `/` alone does NOT save it, because it splits into one segment that is not
// `node_modules` and it would land in the workspace bucket exactly as before. It is caught because a key
// carrying a character npm never writes is a key whose shape is unknown, and an unknown shape is a
// refusal with the key named rather than a placement.
//
// THE FOURTH GENERATION, AND THE THIRD'S TOTALITY ARGUMENT WAS ABOUT THE WRONG FUNCTION. It said, and
// it was right about classifyKey, that totality is not that every key is filed but that no key is filed
// by falling off the end of the tests. classifyLockPackages then dropped keys before classifyKey ever
// ran, on `typeof entry?.version !== "string"`, a guard clause UPSTREAM of all five buckets. Such a key
// is not filed by falling off the end of the tests: it is filed by never reaching them, and no bucket,
// no count and no printed line mentioned it.
//
// MEASURED against this directory's real lockfile with the real node_modules installed,
// exit codes read off the process rather than through a pipe and the lockfile restored by SHA256 rather
// than by eye. Control: unmodified, EXIT 0, all 5 packages compared. Six mutations, ajv the only package
// touched on the first five, EVERY ONE EXIT 0, VERDICT PASS, ajv named nowhere in the output:
//
//   1. `version` deleted from node_modules/ajv                     EXIT 0, "all 4 package(s) resolve"
//   2. `version` written as the JSON number 8.2                    EXIT 0, "all 4 package(s) resolve"
//   3. `version` written as null                                   EXIT 0, "all 4 package(s) resolve"
//   4. the whole entry written as null                             EXIT 0, "all 4 package(s) resolve"
//   5. the entry replaced by { resolved, link: true }              EXIT 0, "all 4 package(s) resolve"
//   6. FOUR of the five stripped of `version`, ajv among them      EXIT 0, "all 1 package(s) resolve"
//
// The fifth is the one that matters most, because `{ resolved, link: true }` is a shape NPM ITSELF
// WRITES. It is not a corruption to be refused; it is the link record for a workspace member, and the
// third generation's own header says so in as many words while its code could not tell that record from
// a malformed entry. Both left by the same door.
//
// SO AN UNREADABLE ENTRY IS A REFUSAL AND A LINK RECORD IS NOT, and telling them apart is the work.
// npm writes one or the other, never both: a link record has NO `version` because nothing was fetched,
// and an install record has a `version` string because something was. So the discriminator is the pair
// rather than either half. `link === true` with no `version` key at all is npm's link record and is set
// aside, named, on the pass line. `link === true` alongside a `version` is a contradiction npm does not
// write, and is refused rather than set aside, because otherwise one added attribute would lift a real
// pin out of the comparison exactly as `optional` once lifted a nested entry out of the tripwire. Every
// other unreadable shape, an absent `version` with no link, a non-string `version`, an entry that is
// null or not an object at all, is refused at exit 2 with the key and the reason printed.
//
// PLACEMENT STILL COMES FIRST. The key is classified before the entry is read, so a key whose SHAPE is
// unknown is refused as unmodelled whatever its entry holds, and a workspace or nested key is filed on
// its path without the entry being consulted at all: neither names a dependency this file resolves, so
// the version it carries is not a fact about anything being compared.
//
// AND THE FLOOR IS BY NAME. `pinned.size > 0` was the only floor, which is why stripping four of five
// still passed: the check exists to pin one specific judge and one is not five. requirePinnedValidator
// now refuses unless JUDGE is in the compared set, and says where it went instead.
//
// THE FIFTH GENERATION, AND THE BY-NAME FLOOR BOUND TO A DIRECTORY RATHER THAN TO A PACKAGE. A
// `packages` key is a PATH. Asking whether the lockfile has a key named node_modules/ajv, and then
// reading a version out of the directory that key names, asks what version the thing sitting in that
// directory is; it never asks what that thing IS. npm has a field for exactly that question and writes
// it precisely when the answer is interesting, and this file read neither it nor the installed
// package.json's own `name`.
//
// So the fifth generation reads the NAME on both sides. From the lockfile: an entry declaring a `name`
// other than its key's is npm's alias record, and it is set aside and printed rather than compared as a
// pin of the directory it sits in. From the installed tree: the package.json's `name` is read and
// compared before its version, because a version is a fact ABOUT a package and which package it is a
// fact about has to be settled first. And the module main() loads is required to resolve inside the
// package directory that was graded, which is the only line tying the two independent resolutions
// together.
//
// WHAT IT STILL CANNOT CLAIM, and this is printed on the pass line rather than left here. A file inside
// the graded package directory may `require` another package and re-export it, and then the judging is
// done by code from somewhere else while every field checked above stays correct. Driven:
// with `ajv/dist/2020.js` rewritten to one line forwarding elsewhere, the run is exit 0 at 112 checks.
// No metadata check can see that, so the pass line says what was read rather than implying identity.
//
// See selfTest for the property assertions that hold this down: each bucket's defining property is
// asserted over the OUTPUT, and the same assertions are run against the superseded rule and required to
// FAIL there, so the control matches the scheme it checks.
//
// readEntry decides WHETHER one entry can be read, and never how. It returns a disposition or a reason,
// so no shape it does not understand can leave through a silent skip.
function readEntry(entry) {
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
    return {
      kind: "unreadable",
      why:
        "its value is " +
        (entry === null ? "null" : Array.isArray(entry) ? "an array" : "the " + typeof entry + " " + JSON.stringify(entry)) +
        " rather than an object, so there is no `version` to read and no `link` to check",
    };
  }
  const hasVersion = Object.prototype.hasOwnProperty.call(entry, "version");
  const isLink = entry.link === true;

  // npm's link record for a workspace member: `{ "resolved": "<repo path>", "link": true }`. It is not a
  // fetch, so it is not a pin, and it carries no version because there was nothing to record.
  if (isLink && !hasVersion) return { kind: "link" };
  if (isLink) {
    return {
      kind: "unreadable",
      why:
        "it carries `link: true` AND a `version`. npm writes one or the other: a link record has no version because nothing was fetched, and an install record has one because something was. Reading this as a link would lift a real pin out of the comparison on the strength of one added attribute",
    };
  }
  if (!hasVersion) {
    return {
      kind: "unreadable",
      why: "it has no `version` and does not carry `link: true`, so it claims an install with nothing to compare it against",
    };
  }
  if (typeof entry.version !== "string") {
    return {
      kind: "unreadable",
      why:
        "its `version` is " +
        (entry.version === null ? "null" : "the " + typeof entry.version + " " + JSON.stringify(entry.version)) +
        " rather than a string, and a version that is not a string is not one this check can compare",
    };
  }
  return { kind: "version", version: entry.version };
}

// classifyKey decides WHERE one key says a thing lives. It never guesses and never defaults.
function classifyKey(key) {
  // WELL-FORMEDNESS BEFORE SEGMENTS, because a key that is not a POSIX relative path has no segments
  // worth reading. npm writes these keys with `/` on Windows as well, and a backslash is not a legal
  // character in a package name either, so a key carrying one is neither a path this can split nor a
  // name npm can have installed.
  if (key.includes("\\")) {
    return {
      where: "unmodelled",
      why: "it carries a backslash. npm writes every `packages` key as a POSIX relative path on all platforms, and a backslash is not legal in a package name, so this is neither a path to split nor a name to resolve",
    };
  }
  const segs = key.split(SEP);
  if (segs.some((s) => s === "" || s === "." || s === "..")) {
    return {
      where: "unmodelled",
      why: "it has an empty, `.` or `..` path segment, so it does not name one location",
    };
  }

  // SEGMENT EQUALITY, not a substring search. This is the line the previous two generations got wrong.
  const first = segs.indexOf(NM_SEG);
  const last = segs.lastIndexOf(NM_SEG);

  if (first === -1) {
    // No install location anywhere in the key, so it names a place in this repository rather than in a
    // tree. In lockfileVersion 2 and 3 the only such keys npm emits are the root, already skipped above,
    // and one per workspace member. Reached only after well-formedness, so this is a decision rather
    // than a fall-through.
    return { where: "workspace" };
  }
  if (last === segs.length - 1) {
    return {
      where: "unmodelled",
      why: "it ends at a node_modules directory and names no package inside it",
    };
  }
  if (first !== 0) {
    return { where: "nested", why: "the install sits under the prefix " + segs.slice(0, first).join(SEP) };
  }
  if (last !== 0) {
    return { where: "nested", why: "a second node_modules segment at depth " + last };
  }

  // Everything after the one leading node_modules is the package name, and npm's grammar allows exactly
  // two shapes for it. Anything else is a key this check cannot turn into something to resolve, and
  // saying so is better than resolving a name npm could not have installed and calling it missing.
  const name = segs.slice(1);
  if (name.length === 1 && !name[0].startsWith("@")) return { where: "top", name: name[0] };
  if (name.length === 2 && name[0].startsWith("@")) return { where: "top", name: name.join(SEP) };
  return {
    where: "unmodelled",
    why: "the package part " + name.join(SEP) + " is neither a bare name nor one @scope/name pair",
  };
}

// aliasOf answers one question about a top-level install entry: does the LOCKFILE ITSELF say this
// directory holds a package other than the one the directory is named for. npm writes a `name` inside
// the entry exactly when it does, which is the alias install `npm i ajv@npm:other@1.2.3`, and the field
// is npm's own way of saying the directory name is not the package name. VERIFIED by running npm rather
// than read off documentation: `npm i ajv@npm:fast-deep-equal@3.1.3` writes
// "node_modules/ajv": { "name": "fast-deep-equal", "version": "3.1.3", ... } and installs a package.json
// declaring fast-deep-equal at that path.
//
// A `name` EQUAL to the directory's own name is not an alias and is not treated as one: npm writes that
// harmlessly for some specs, and the fact it records is the one the key already carries.
function aliasOf(name, entry) {
  if (typeof entry.name !== "string" || entry.name === name) return null;
  return entry.name;
}

function classifyLockPackages(packages) {
  const pinned = new Map();
  const excluded = [];
  const linked = [];
  const aliased = [];
  const nested = [];
  const workspaces = [];
  const unmodelled = [];
  const unreadable = [];
  const roots = [];
  for (const [key, entry] of Object.entries(packages ?? {})) {
    // FILED, NOT SKIPPED. The root key is the one key with nothing to compare, and saying so by putting
    // it in a bucket rather than by leaving the loop is what lets the caller check that every key the
    // map holds was accounted for. A `continue` here would be indistinguishable, from the outside, from
    // the drop this generation exists to remove.
    if (key === "") {
      roots.push(key);
      continue;
    }
    const at = classifyKey(key);
    // PLACEMENT IS DECIDED BEFORE THE ENTRY IS READ, and before the exclusion. Whether npm was entitled
    // to skip an install, and whether the entry can be read at all, are both questions ABOUT AN INSTALL,
    // so neither is reachable until the key has been placed as one. Asking the exclusion first let an
    // optional NESTED entry leave as an exclusion, which meant the nested tripwire could be disarmed by
    // an attribute; asking the version first let ANY entry leave before it was placed at all.
    if (at.where === "unmodelled") {
      unmodelled.push({ key, why: at.why });
      continue;
    }
    if (at.where === "nested") {
      nested.push(key);
      continue;
    }
    if (at.where === "workspace") {
      // A repository path names no dependency this file resolves, so its entry is not consulted: the
      // version a workspace member carries is not a fact about anything being compared.
      workspaces.push(key);
      continue;
    }
    const read = readEntry(entry);
    if (read.kind === "unreadable") {
      unreadable.push({ key, why: read.why });
      continue;
    }
    if (read.kind === "link") {
      linked.push(at.name);
      continue;
    }
    // THE ALIAS RECORD, and it is filed BEFORE the exclusion for the reason the exclusion was moved
    // below the nesting test: an attribute must not be able to lift an entry out of the bucket that
    // exists to notice it. `optional: true` on an aliased entry would otherwise print the directory's
    // name in the excluded list and never say that the directory holds another package at all.
    const alias = aliasOf(at.name, entry);
    if (alias !== null) {
      aliased.push({ key, name: at.name, declared: alias });
      continue;
    }
    if (entry.optional === true || entry.os !== undefined || entry.cpu !== undefined) {
      excluded.push(at.name);
      continue;
    }
    pinned.set(at.name, read.version);
  }
  return { pinned, excluded, linked, aliased, nested, workspaces, unmodelled, unreadable, roots };
}

// Where the judge ended up, when it did not end up compared. Read off the classifier's own output, so it
// reports the placement that actually happened rather than re-deriving one.
function whereJudgeWent(result, packages) {
  if (result.pinned.has(JUDGE)) return null;
  if (result.excluded.includes(JUDGE)) return "excluded as optional or platform-gated";
  if (result.linked.includes(JUDGE)) return "set aside as a workspace link record, which is not a pin";
  const alias = (result.aliased ?? []).find((a) => a.name === JUDGE);
  if (alias !== undefined) {
    return (
      "set aside as an npm ALIAS record: the lockfile's own entry for " +
      alias.key +
      " declares the name " +
      JSON.stringify(alias.declared) +
      ", which is npm saying that directory holds a different package. So the lockfile pins " +
      JSON.stringify(alias.declared) +
      " there and pins no " +
      JUDGE +
      " at all"
    );
  }
  const keyed = (list, pred) => list.filter(pred);
  const asKey = NM + JUDGE;
  const scoped = (k) => k === asKey || k.startsWith(asKey + SEP) || k.split(SEP).includes(JUDGE);
  const inNested = keyed(result.nested, scoped);
  if (inNested.length > 0) return "refused as a nested entry: " + inNested.join(", ");
  const inWork = keyed(result.workspaces, scoped);
  if (inWork.length > 0) return "set aside as a workspace path: " + inWork.join(", ");
  const named = Object.keys(packages ?? {}).filter(scoped);
  if (named.length > 0) return "named by the key(s) " + named.join(", ") + ", which reached no compared bucket";
  return "not named by any key in the lockfile at all";
}

// THE COMPARISON, AND IT IS ABOUT A PACKAGE RATHER THAN ABOUT A DIRECTORY. A lockfile `packages` key is
// a PATH. Reading a version out of the directory that path names asks "what version is the thing sitting
// here", and the check exists to ask "is the package this repository pinned the one that will judge".
// Those are the same question only while nobody has put something else in the directory.
//
// MEASURED, three trees, each hand-built from this directory's own lockfile with a stub in
// place of the judge, exit codes read off the process and the tree restored from a tar snapshot and
// re-digested to sha256 2359805d... after each:
//
//   1. an npm ALIAS install, the lockfile entry and the installed package.json both declaring
//      not-ajv-at-all 9.9.9                                        EXIT 0, PASS, 112 checks
//   2. the installed package.json alone declaring corporate-schema-tool 8.20.0,
//      the lockfile untouched                                      EXIT 0, PASS, 112 checks
//   3. `ajv/dist/2020.js` rewritten to re-export another package   EXIT 0, PASS, 112 checks
//
// The first two are what this function closes: both are caught by reading the installed `name`. The
// alias is caught one stage earlier still, in classifyLockPackages, because there the LOCKFILE ITSELF
// says the directory holds another package and a check that ignored it would be ignoring evidence in the
// file it is reading. THE THIRD IS NOT CLOSED AND CANNOT BE, which is stated on the pass line rather
// than left as a comment: nothing about a package's metadata constrains what its files re-export.
//
// THE PROBE IS INJECTED so this function is pure and `--self-test` can drive the real one over trees
// that do not exist on disk. A control that re-implements the rule it is checking agrees with itself.
function compareInstalled(pinned, probe) {
  const verified = new Map();
  const absent = [];
  const wrong = [];
  const misnamed = [];
  const unreadable = [];
  const unidentifiable = [];
  for (const [name, want] of pinned) {
    const got = probe(name);
    if (got.kind === "absent") {
      absent.push({ name, want });
      continue;
    }
    if (got.kind === "unreadable") {
      unreadable.push({ name, want, why: got.why });
      continue;
    }
    // NAME BEFORE VERSION, and the order is the finding rather than a style. A version is a fact ABOUT a
    // package, so which package it is a fact about has to be settled first. Comparing the version of an
    // unidentified thing is what let a directory named `ajv` holding another package at 8.20.0 pass.
    if (typeof got.name !== "string" || got.name === "") {
      unidentifiable.push({ name, want, why: "its package.json declares no `name` string (saw " + JSON.stringify(got.name) + ")" });
      continue;
    }
    if (typeof got.version !== "string" || got.version === "") {
      unidentifiable.push({ name, want, why: "its package.json declares no `version` string (saw " + JSON.stringify(got.version) + ")" });
      continue;
    }
    if (got.name !== name) {
      misnamed.push({ name, want, declared: got.name, version: got.version });
      continue;
    }
    if (got.version !== want) {
      wrong.push({ name, want, got: got.version });
      continue;
    }
    verified.set(name, { name: got.name, version: got.version, at: got.at });
  }
  return { verified, absent, wrong, misnamed, unreadable, unidentifiable };
}

// The filesystem half, kept apart from the rule above so the rule can be driven offline.
//
// The two failure modes of resolving "<name>/package.json" are NOT the same thing and are not reported
// as the same thing. A package that is not installed fails both probes and is a finding. A package that
// IS installed but whose `exports` map declines to expose ./package.json fails only the second, and
// calling that one missing would put a false red on a tree that npm ci had just built correctly. The
// second case is a refusal: the identity cannot be read, so no opinion can be formed about it.
function probeInstalled(name) {
  let at;
  let raw;
  try {
    at = requireHere.resolve(name + "/package.json");
    raw = fs.readFileSync(at, "utf8");
  } catch {
    try {
      requireHere.resolve(name);
    } catch {
      return { kind: "absent" };
    }
    return { kind: "unreadable", why: "installed, but its own package.json could not be resolved or read" };
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return { kind: "unreadable", why: "its package.json is installed but does not parse: " + err.message };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { kind: "unreadable", why: "its package.json parses to something that is not an object" };
  }
  return { kind: "read", name: parsed.name, version: parsed.version, at };
}

// resolvesInside answers whether a resolved module file sits inside a resolved package's own directory.
// Both arguments are absolute paths that have already been realpath'd by the caller.
//
// SEPARATOR-TERMINATED, for the same reason classifyKey compares whole segments rather than searching
// for a substring: `/n/ajv-extra/dist/x.js` starts with `/n/ajv` and is a different package.
function resolvesInside(pkgJsonPath, modulePath) {
  const dir = path.dirname(pkgJsonPath);
  return modulePath.startsWith(dir.endsWith(path.sep) ? dir : dir + path.sep);
}

// Returns null when the module main() loads sits inside the judge package that was graded, and otherwise
// the reason it does not. Both paths are realpath'd, so a symlinked package directory, which is what npm
// workspaces and pnpm write, is compared by where it actually is rather than by how it was reached.
function judgeModuleWithinGradedPackage() {
  let pkgJson;
  let modFile;
  try {
    pkgJson = fs.realpathSync(requireHere.resolve(JUDGE + "/package.json"));
  } catch (err) {
    return JUDGE + "/package.json no longer resolves, having resolved a moment ago: " + err.message;
  }
  try {
    modFile = fs.realpathSync(requireHere.resolve(AJV_MODULE));
  } catch (err) {
    return AJV_MODULE + " does not resolve at all, so the module this file is about to load is not present: " + err.message;
  }
  if (!resolvesInside(pkgJson, modFile)) {
    return AJV_MODULE + " resolves to " + modFile + ", which is outside the graded package directory " + path.dirname(pkgJson);
  }
  return null;
}

// CONTAINMENT FOR ALL FIVE PINS, AND NOT ONLY THE JUDGE. The check above was written for one specifier
// and one package, and the other four pinned packages had no containment test of any kind. MEASURED on
// against this directory's real tree, ONE FIELD EDITED, `main` in
// node_modules/fast-uri/package.json set to "../../../ieitg-marker.js": `require.resolve("fast-uri")`
// then returns a file in the repository's own scripts/ directory, OUTSIDE node_modules entirely, that
// file executed inside this gate's own process and wrote a marker naming this process's pid and argv[1],
// and the run was EXIT 0 at 112 checks with fast-uri still printed among the packages compared by name
// and version. Nothing in the package.json the comparison reads had changed, because `main` is not
// `name` and is not `version`.
//
// THE DISCLOSED RESIDUAL DID NOT DESCRIBE THAT. It said a file INSIDE the graded directory could
// re-export another package. The file that ran was not inside the graded directory and was not inside
// node_modules, so the sentence was narrower than the hole it was disclosing.
//
// THE RULE IS THE JUDGE'S RULE APPLIED TO EVERY PINNED NAME: the file node would load for a bare
// `require("<name>")` must sit inside the realpath'd directory of the package.json that was graded under
// that name. It runs BEFORE anything is loaded, so this escape is refused rather than merely noticed
// afterwards.
//
// THE RESOLVER IS INJECTED so `--self-test` drives the real rule over trees that do not exist on disk. A
// control that re-implements the rule it is checking agrees with itself and with nothing else.
//
// FOUR OUTCOMES AND NO DEFAULT ARM, and the arithmetic below closes against the input, so a name that
// reaches none of them is a refusal naming the shortfall rather than a pin that quietly went ungraded.
// `no-entry` is a real and honest outcome rather than a hole: a package whose `exports` map declines to
// expose "." cannot be loaded by bare name at all, so nothing can escape through an entry it does not
// have. It is PRINTED rather than dropped, on this file's standing rule that a check which silently
// discards entries is one that can pass having examined less than it says.
function entryContainment(names, resolveEntry) {
  const contained = [];
  const outside = [];
  const noEntry = [];
  const unresolvable = [];
  for (const name of names) {
    const r = resolveEntry(name);
    if (r.kind === "no-entry") {
      noEntry.push({ name, why: r.why });
      continue;
    }
    if (r.kind === "unresolvable") {
      unresolvable.push({ name, why: r.why });
      continue;
    }
    if (!resolvesInside(r.pkgJson, r.entry)) {
      outside.push({ name, entry: r.entry, dir: path.dirname(r.pkgJson) });
      continue;
    }
    contained.push({ name, entry: r.entry });
  }
  return { contained, outside, noEntry, unresolvable };
}

// The filesystem half of entryContainment, kept apart so the rule can be driven offline. Both paths are
// realpath'd for the same reason the judge's are: a symlinked package directory is what npm workspaces
// and pnpm write, and comparing how a path was reached rather than where it lands is a false red.
function resolveEntryOnDisk(name) {
  let pkgJson;
  try {
    pkgJson = fs.realpathSync(requireHere.resolve(name + SEP + "package.json"));
  } catch (err) {
    return { kind: "unresolvable", why: name + "/package.json no longer resolves, having resolved a moment ago: " + err.message };
  }
  let entry;
  try {
    entry = fs.realpathSync(requireHere.resolve(name));
  } catch (err) {
    if (err.code === "ERR_PACKAGE_PATH_NOT_EXPORTED") {
      return { kind: "no-entry", why: "its `exports` map does not expose \".\", so it cannot be loaded by bare name" };
    }
    return { kind: "unresolvable", why: "its package.json resolves but `require(" + JSON.stringify(name) + ")` does not: " + err.message };
  }
  return { kind: "resolved", pkgJson, entry };
}

// AND THE CHECK THAT READS WHAT ACTUALLY RAN, which is the only one of these that is not a claim about
// metadata. Everything above asks the filesystem a question about names, versions and where a specifier
// POINTS. This asks the running process which files it LOADED.
//
// IT IS HERE BECAUSE EXTENDING CONTAINMENT WAS NOT ENOUGH, and that was measured rather than reasoned.
// MEASURED, `main` left alone at "index.js" so entry containment is satisfied, and instead
// ONE `require` of a path climbing three levels out prepended to node_modules/fast-uri/index.js: the
// entry resolves inside its own package, every metadata field is correct, and a file in the repository's
// scripts/ directory again executed inside this gate's process while the run was EXIT 0 at 112 checks.
// A containment fix alone would have bought a new disclosure sentence that was narrower than the hole
// for the second time, which is the defect this check exists to stop rather than to restate.
//
// THE POSITIVE CONTROL IS INSIDE THE INSTRUMENT, because a census over an empty cache files nothing,
// finds nothing foreign and passes. `mustInclude` is a module this process demonstrably loaded, so a
// walk that does not visit it is REFUSED as an instrument fault rather than reported as a clean result.
// A walk that never visits and a guard clause upstream of the tests are the same defect.
//
// EXIT 1 AND NOT 2 when something foreign is loaded: this is an answer, not a refusal to answer. Code
// from outside every package the lockfile pins was executed by the process that grades the vectors.
//
// `permitted` IS AN EXACT-PATH LIST AND IS TRIED BEFORE THE DIRECTORIES, so the repository's own entry
// point, its preload and its shared guard are filed as themselves. It is counted and printed rather than
// subtracted from the population, because the arithmetic below closes against the input: a key that left
// through a bucket nobody counts is how a census passes having examined less than it says. Every other
// path, including every other file in the same directories, stays foreign.
function loadedModuleVerdict(cacheKeys, gradedDirs, mustInclude, permitted) {
  const inside = new Map();
  const foreign = [];
  const own = [];
  for (const key of cacheKeys) {
    if (permitted.includes(key)) {
      own.push(key);
      continue;
    }
    const dir = gradedDirs.find((d) => key === d || key.startsWith(d.endsWith(path.sep) ? d : d + path.sep));
    if (dir === undefined) {
      foreign.push(key);
      continue;
    }
    inside.set(dir, (inside.get(dir) ?? 0) + 1);
  }
  let filed = foreign.length + own.length;
  for (const n of inside.values()) filed += n;
  if (filed !== cacheKeys.length) {
    return { kind: "refuse", why: cacheKeys.length + " loaded module(s) were censused and " + filed + " were filed, so this census cannot say what it found for the rest" };
  }
  if (!cacheKeys.includes(mustInclude)) {
    return {
      kind: "refuse",
      why: "the census did not visit " + mustInclude + ", which this process had already loaded, so it was walking something other than what ran",
    };
  }
  if (foreign.length > 0) return { kind: "fail", foreign, inside, own, total: cacheKeys.length };
  return { kind: "ok", inside, own, total: cacheKeys.length };
}

// AND THE CONTROL ON THE RECORDER'S STARTING POINT, which is a different question from the one
// censusPopulation asks. That one asks whether the cache holds anything the recorder missed, and it
// catches a pre-arming CommonJS load because such a load is in the cache. A pre-arming ES load is in
// neither the record nor the cache, so no comparison between those two can see it.
//
// WHAT CAN SEE IT IS THE ENTRY POINT ITSELF. The recorder is armed by an `--import` preload, before node
// resolves the entry point, so the entry point's own load is filed like any other. If it is not in the
// population then arming began at some later moment, and everything loaded before that moment is outside
// what this census can speak for, whichever module system it arrived through.
//
// EXIT 2 AND NOT 1: nothing is known to be wrong with the tree. What is not known is where the record
// starts, and a census whose population begins in an unknown place is a could-not-check.
function entryObservedVerdict(populationKeys, entryPath) {
  if (populationKeys.includes(entryPath)) return { kind: "ok" };
  return {
    kind: "refuse",
    why:
      "the load record does not contain this file, " +
      entryPath +
      ", so the recorder was armed after this file loaded rather than before it, and anything loaded in " +
      "between is in neither the record nor the require cache",
  };
}

// censusPopulation decides WHAT loadedModuleVerdict is asked about, and it is a separate function from
// the rule that judges it for the same reason probeInstalled is separate from compareInstalled: the
// population can then be driven over records that never happened.
//
// THE UNION IS THE POINT. A key the recorder saw and the cache no longer holds is a module that was
// loaded and then removed from the cache, which is bypass one; a key the recorder saw that could never
// have been in the cache is an ES module, which is bypass two. Both are in the population because the
// population is built by adding, and nothing downstream subtracts.
//
// FOUR KINDS OF URL AND NO DEFAULT ARM. A `node:` URL is a Node builtin: it is SET ASIDE AND COUNTED
// rather than dropped, because a builtin cannot be a file this repository ships and the count is
// printed so the exemption is visible instead of silent. A `file:` URL contributes its resolved real
// path, which is the same spelling the cache uses, so the two sources can be compared at all. Any other
// URL contributes ITSELF as its key, so a `data:` import, which executes source under no path
// whatever, arrives at the comparison as something that cannot be inside a graded directory rather
// than being filtered out on the way there. Driven: `import("data:text/javascript,...")` reaches this
// hook.
//
// THE RECORDER CARRIES ITS OWN POSITIVE CONTROL, exactly as the cache walk carries `mustInclude`. If
// the cache holds a key the recorder never saw, the recorder was armed after something loaded or it is
// not recording what runs, and this REFUSES rather than reporting the union it happens to have. Without
// it a recorder that quietly recorded nothing would still pass on the cache alone, which is precisely
// the pass the two bypasses already bought once.
//
// AND AN EMPTY POPULATION REFUSES. A census that resolved its two inputs and found nothing to census
// has checked nothing, and reporting that as containment is the defect this whole check exists for.
function censusPopulation(recordedUrls, cacheKeys, toPath) {
  const builtins = [];
  const recordedKeys = [];
  for (const url of recordedUrls) {
    if (url.startsWith("node:")) {
      builtins.push(url);
      continue;
    }
    recordedKeys.push(url.startsWith("file:") ? toPath(url) : url);
  }

  const seen = new Set(recordedKeys);
  const unseen = cacheKeys.filter((k) => !seen.has(k));
  if (unseen.length > 0) {
    return {
      kind: "refuse",
      why:
        "the load recorder did not see " +
        unseen.length +
        " module(s) the require cache still holds (" +
        unseen.slice(0, 3).join(", ") +
        "), so it was armed after something loaded rather than before it and cannot say what ran",
    };
  }

  const keys = [...new Set([...recordedKeys, ...cacheKeys])];
  if (keys.length === 0) {
    return {
      kind: "refuse",
      why: "the census population is empty: the recorder filed nothing and the cache holds nothing, so this run has no loaded module to have an opinion about",
    };
  }

  const inCache = new Set(cacheKeys);
  return { kind: "ok", keys, builtins, outsideCache: keys.filter((k) => !inCache.has(k)) };
}

// THE VALIDATOR IS PART OF THE CLAIM, which is why this check lives in this file and not in a separate
// gate. Everything below asserts that the frozen downpipe/0.1.0 vectors match docs/format/schema.json,
// and that assertion is only as pinned as the ajv that made it. An ajv the lockfile does not name is a
// different judge, and a PASS it produced says something narrower than this file claims to say. So the
// pin is checked here, before a single vector is read, rather than being left to the environment.
//
// WHY NOT THE SIBLING GATE. Other repositories in this product's codebase carry a gate script that
// compares node_modules/.package-lock.json against package-lock.json as the first step of `npm run
// lint:biome`. It earns its place there because those repositories run long chains of npm scripts against
// whatever happens to be installed, so a tree behind the lock comes back as exit 127 and reads like broken
// code. This repository has no such chain. Its npm surface is this one directory.
//
// THE COUNT IN THIS PARAGRAPH WAS WRONG AND IS NOW ENUMERATED, because the argument for having no
// repository-level deps gate rests on it. It used to say BOTH of the two things that use this directory
// reinstall first. There are six, and four of them do not reinstall:
//
//   1. `make schema-validate`                     npm ci, then npm run validate      READS node_modules
//   2. CI job Schema (ajv vectors)                npm ci, then npm run validate      READS node_modules
//   3. CI job Vulnerabilities, the npm audit step no install at all                  lockfile only
//   4. scripts/verdict-guard-gate.mjs             no install at all                  package.json only
//   5. CI job Schema, the self-test step          no install at all                  lockfile only
//   6. `make schema-validate-selftest`            no install at all                  lockfile only
//
// Number 4 is the least obvious and is listed because it is easy to miss: the verdict-guard gate parses
// this directory's package.json to reach validate.mjs through `cd <dir> && npm run <name>`, which is the
// only channel by which this file is named as an entry point at all. It reads a manifest, never a tree.
//
// THE ARGUMENT SURVIVES THE CORRECTION, and it survives on a measurement rather than on the count. What
// a deps gate would protect is a consumer that READS node_modules without reinstalling, and there is
// still no such consumer: 1 and 2 are the only two that read it and both reinstall immediately before.
// Numbers 3 to 6 read the lockfile or the manifest and never the installed tree, and that was verified
// rather than assumed, in a directory holding package.json and package-lock.json and NO
// node_modules at any level up the tree: `npm audit --audit-level=low` runs and reports, and
// `node validate.mjs --self-test` passes all of its assertions. A zero from a tool that read nothing
// would have looked identical, so the audit was given a known-positive control on that same empty
// directory: rolled back to the pre-cd6a7797 pins, ajv 8.17.1 and fast-uri 3.1.2, it exits 1 and names
// all four advisories, three of them HIGH. So the zero on the real lockfile is a read zero rather than
// a vacuous one.
//
// Copying docs' 391-line gate plus its self-test into a Go repository to watch a five-package tree whose
// only two node_modules consumers reinstall on every use would still be more machinery than the question
// has. The gap that is real is narrower: `npm run validate` on its own, which is what a reader does when
// they believe the install was a one-off, will happily judge the format under an unpinned ajv. That is
// the gap this function closes. A consumer that READS node_modules without reinstalling would change
// the answer, and that is the thing to watch for rather than the arrival of another consumer at all.
// The count in the list above moved from two to six without weakening the argument, so the count is not
// the test.
//
// MEASURED, so this is a recurrence guard rather than a precaution. the shared checkout
// resolved ajv 8.17.1 and fast-uri 3.1.2 while the lockfile named 8.20.0 and 3.1.5, and it had done since
// 8 August with nothing in the repository noticing. Those two versions are not an arbitrary drift: commit
// cd6a7797 moved the pin precisely to clear four advisories, three of them HIGH, all of them in the
// production tree because ajv is the only dependency there is. The tree still returned PASS, which is the
// part worth stating plainly, so the staleness was invisible from the output as well as from the exit code.
//
// EXIT CODES ARE THREE-VALUED. 0 is a checked pass and the run continues. 1 is a definite finding with a
// remedy: a package the lock names is not installed, or is installed at another version. 2 is a REFUSAL,
// meaning no opinion could be formed at all, and it is used only where that is true, on five arms: a
// lockfile that is absent, one that will not parse, one that names nothing to compare, one carrying a
// nested entry this check does not model, and a package that is installed but declines to expose its own
// package.json so its version cannot be read.
//
// A merely stale tree is 1 and not 2, because this check verifies the environment, so a wrong environment
// is its finding rather than an obstacle to it. The refusals go the other way for the same reason: none of
// them knows anything to be wrong with the tree, so calling any of them a failure would be an accusation
// the evidence does not support.
//
// NO NAME CAP, deliberately. The sibling gate sliced its list to five while printing a count of six, so
// the sixth package went unnamed by the gate complaining about it. This lockfile has five entries and its
// whole dependency closure is ajv's, so every name fits and a cap here would be a defect waiting for a
// lockfile that will not arrive.
function requirePinnedValidator() {
  const notYourCode =
    "  This is a DEPENDENCY PIN finding, not a schema or vector one. It runs before docs/format/schema.json\n" +
    "  is opened, so nothing here says anything about the schema, the vectors or your changes to them.";

  if (!fs.existsSync(LOCK_PATH)) {
    console.error("REFUSED: there is no package-lock.json at " + LOCK_PATH + ", so the validator has no pin to be held to.");
    console.error(notYourCode);
    console.error("\n  Exit 2 rather than 1: this is a refusal to answer, not an answer of no. This directory commits");
    console.error("  its lockfile, so an absent one means the checkout is incomplete rather than the tree stale.");
    verdictSkipped("no package-lock.json at " + LOCK_PATH + ", so the ajv pin could not be checked", { canonicalTo: "stderr" });
    process.exit(2);
  }

  let lock;
  try {
    lock = JSON.parse(fs.readFileSync(LOCK_PATH, "utf8"));
  } catch (err) {
    console.error("REFUSED: " + LOCK_PATH + " exists but would not parse as JSON.\n  " + err.message);
    console.error(notYourCode);
    console.error("\n  Exit 2 rather than 1: no opinion was formed on the tree, because it was never compared.");
    verdictSkipped("package-lock.json would not parse, so the ajv pin could not be checked: " + err.message, { canonicalTo: "stderr" });
    process.exit(2);
  }

  // THE SHAPE OF THE FILE BEFORE THE SHAPE OF ITS KEYS. Everything classifyKey knows is the
  // lockfileVersion 2 and 3 key grammar: a `packages` map, `node_modules/<name>` install paths, a
  // repository path per workspace member, a `link: true` record beside each. lockfileVersion 1 has no
  // `packages` map at all, and a version this file has never seen may mean the grammar moved under it.
  //
  // Measured: setting lockfileVersion to 9 and touching nothing else was EXIT 0 with all
  // five packages still compared, because the field was never read. That is a model asserting itself
  // against a document that no longer claims to be the thing it models. It is a REFUSAL rather than a
  // finding, because nothing is known to be wrong with the tree: what is not known is whether the keys
  // still mean what this file reads them to mean.
  if (!Number.isInteger(lock.lockfileVersion) || !MODELLED_LOCKFILE_VERSIONS.includes(lock.lockfileVersion)) {
    console.error("REFUSED: " + LOCK_PATH + " declares lockfileVersion " + JSON.stringify(lock.lockfileVersion) + ", and this");
    console.error("  check models only " + MODELLED_LOCKFILE_VERSIONS.join(" and ") + ". Its whole key grammar is that version's: a `packages` map keyed by");
    console.error("  `node_modules/<name>` install paths and by repository paths for workspace members. Reading a");
    console.error("  document of another version with this grammar would place keys by what they used to mean.");
    console.error(notYourCode);
    console.error("\n  REMEDY: confirm the `packages` key grammar for that lockfileVersion and add it to");
    console.error("  MODELLED_LOCKFILE_VERSIONS, or regenerate the lockfile with an npm that writes one of them.");
    console.error("\n  Exit 2 rather than 1: nothing is known to be wrong with the tree.");
    verdictSkipped("package-lock.json declares an unmodelled lockfileVersion, so the ajv pin could not be checked", { canonicalTo: "stderr" });
    process.exit(2);
  }
  if (lock.packages === null || typeof lock.packages !== "object" || Array.isArray(lock.packages)) {
    console.error("REFUSED: " + LOCK_PATH + " has no `packages` object to read: it is " + (lock.packages === undefined ? "absent" : Array.isArray(lock.packages) ? "an array" : JSON.stringify(lock.packages)) + ".");
    console.error("  A lockfileVersion " + lock.lockfileVersion + " document carries one, so this is not a lockfile of the shape it declares.");
    console.error(notYourCode);
    console.error("\n  REMEDY: regenerate it with `npm install` in " + SELF_DIR + ".");
    console.error("\n  Exit 2 rather than 1: nothing was compared, so nothing is being alleged about the tree.");
    verdictSkipped("package-lock.json has no `packages` object, so the ajv pin could not be checked", { canonicalTo: "stderr" });
    process.exit(2);
  }

  const {
    pinned,
    excluded,
    linked,
    aliased,
    nested,
    workspaces,
    unmodelled,
    unreadable: unreadableEntries,
    roots,
  } = classifyLockPackages(lock.packages);
  // BEFORE EVERY OTHER REFUSAL, alongside the unmodelled one, because this is the arm that did not exist
  // at all. An entry the classifier cannot read used to leave through a guard clause upstream of all five
  // buckets, so a pin could be removed from the comparison by deleting one field and the run would pass
  // saying nothing about it whatever. Exit 2 with the key and the reason printed is the honest answer,
  // and it is a refusal rather than a finding because nothing here is known to be wrong with the tree.
  if (unreadableEntries.length > 0) {
    console.error("REFUSED: " + LOCK_PATH + " has " + unreadableEntries.length + " package entry/entries this check");
    console.error("  cannot read, so it cannot say what version they claim and will not pass over them in silence.");
    for (const u of unreadableEntries) console.error("    " + JSON.stringify(u.key) + "\n      " + u.why);
    console.error(notYourCode);
    console.error("\n  REMEDY: an install entry npm wrote carries a `version` string. Its link record for a workspace");
    console.error("  member carries `link: true` and no version, and that is set aside rather than refused. If these");
    console.error("  entries were hand-edited, restore them with `npm install`.");
    console.error("\n  Exit 2 rather than 1: nothing is known to be wrong with the tree. What is not known is what");
    console.error("  these entries claim, and reading past them unread is how a pin goes uncompared.");
    verdictSkipped("package-lock.json has package entries the ajv pin check cannot read", { canonicalTo: "stderr" });
    process.exit(2);
  }
  // FIRST, BEFORE THE OTHER REFUSALS, because a key whose shape is unknown is the one case where this
  // file previously formed an opinion it had no basis for. It was not a refusal at all: an unrecognised
  // key fell through to the workspace arm and was reported as set aside, so a pin could be removed from
  // the comparison and the run would still pass while naming the key on the pass line. Exit 2 with the
  // key printed is the honest answer, and it is a refusal rather than a finding because nothing here is
  // known to be wrong with the installed tree.
  if (unmodelled.length > 0) {
    console.error("REFUSED: " + LOCK_PATH + " has " + unmodelled.length + " package key(s) whose shape this");
    console.error("  check does not model, so it cannot say where they claim to be installed and will not guess.");
    for (const u of unmodelled) console.error("    " + JSON.stringify(u.key) + "\n      " + u.why);
    console.error(notYourCode);
    console.error("\n  REMEDY: a `packages` key npm wrote is a POSIX relative path, either a repository path for a");
    console.error("  workspace member or one or more `node_modules/<name>` steps. If npm produced these, this check");
    console.error("  needs teaching. If they were hand-edited, restore them with `npm install`.");
    console.error("\n  Exit 2 rather than 1: nothing is known to be wrong with the tree. What is not known is what");
    console.error("  these keys are asking about, and setting them aside unread is how a pin goes uncompared.");
    verdictSkipped("package-lock.json has package keys whose shape the ajv pin check does not model", { canonicalTo: "stderr" });
    process.exit(2);
  }
  if (nested.length > 0) {
    console.error("REFUSED: " + LOCK_PATH + " has " + nested.length + " nested package entry/entries, which this");
    console.error("  check does not model. Resolving one from this file would reach the top-level copy of the same");
    console.error("  name and grade a package the lockfile was not asking about, so it declines rather than guess.");
    for (const n of nested) console.error("    " + n);
    console.error(notYourCode);
    console.error("\n  REMEDY: teach requirePinnedValidator to resolve a nested entry from inside its parent, or");
    console.error("  flatten the tree. Do not delete this arm to make it quiet.");
    console.error("\n  Exit 2 rather than 1: nothing is known to be wrong with the tree, only that this check");
    console.error("  cannot honestly grade the shape it has been given.");
    verdictSkipped("package-lock.json has nested package entries, which the ajv pin check does not model", { canonicalTo: "stderr" });
    process.exit(2);
  }
  if (pinned.size === 0) {
    console.error("REFUSED: " + LOCK_PATH + " parsed but names no required packages, so nothing was compared");
    console.error("  and a pass here would have meant nothing.");
    console.error(notYourCode);
    verdictSkipped("package-lock.json names no required packages, so the ajv pin could not be checked", { canonicalTo: "stderr" });
    process.exit(2);
  }

  // THE FLOOR BY NAME, and it is the floor that was missing. `pinned.size > 0` asks only that SOMETHING
  // was compared, and something is not this. MEASURED: stripping the `version` from four of
  // the five entries, ajv among them, left one package compared and exited 0 with "all 1 package(s)
  // resolve" on the pass line. Every claim this file goes on to make about docs/format/schema.json is a
  // claim ajv made, so a run that did not compare ajv graded the frozen downpipe/0.1.0 vectors under a
  // validator this repository did not pin, whatever else it compared and however many.
  //
  // A REFUSAL AND NOT A FINDING, on this file's own three-valued convention: nothing here is known to be
  // wrong with the installed tree. What is missing is the question, not the answer.
  const judgeWent = whereJudgeWent({ pinned, excluded, linked, aliased, nested, workspaces }, lock.packages);
  if (judgeWent !== null) {
    console.error("REFUSED: " + LOCK_PATH + " does not offer " + JUDGE + " as a package to compare, so the one pin");
    console.error("  this check exists to hold was never checked. It was " + judgeWent + ".");
    console.error("  " + pinned.size + " other package(s) were compared, and comparing them says nothing about the validator.");
    console.error(notYourCode);
    console.error("\n  REMEDY: " + JUDGE + " is this directory's only direct dependency and the module main() loads is");
    console.error("  `" + AJV_MODULE + "`. If it has genuinely been replaced, change JUDGE in this file to name the");
    console.error("  package that now makes the claim. Do not delete this arm: it is the whole floor.");
    console.error("\n  Exit 2 rather than 1: nothing is known to be wrong with the tree. The pin simply went ungraded,");
    console.error("  and a pass counting the other packages would have been affirmative about a question never asked.");
    verdictSkipped(JUDGE + " was not among the packages compared, so the validator pin could not be checked", { canonicalTo: "stderr" });
    process.exit(2);
  }

  // Resolution rather than a directory listing, on purpose: this reports the copy node would actually
  // load from here, so a tree that resolves upward to a parent directory is graded as what it will run
  // rather than as an empty node_modules.
  const compared = compareInstalled(pinned, probeInstalled);

  // THE ARITHMETIC CLOSES ON THE COMPARISON, and this arm is here because of the shape that has now
  // defeated three fixes in this family: a `continue` upstream of the tests, which files nothing, counts
  // nothing and prints nothing. Every pinned name must leave compareInstalled through exactly one of its
  // six outcomes, so a future edit that adds a seventh path and forgets it is a refusal here rather than
  // a pin that quietly went ungraded. selfTest drives the same identity over its own corpus.
  const accounted =
    compared.verified.size +
    compared.absent.length +
    compared.wrong.length +
    compared.misnamed.length +
    compared.unreadable.length +
    compared.unidentifiable.length;
  if (accounted !== pinned.size) {
    console.error("REFUSED: " + pinned.size + " package(s) were handed to the installed-tree comparison and " + accounted);
    console.error("  came back with an outcome. " + (pinned.size - accounted) + " reached none, so this check cannot say");
    console.error("  what it found for them. This is an internal inconsistency in the check.");
    console.error(notYourCode);
    verdictSkipped("the installed-tree comparison did not account for every pinned package", { canonicalTo: "stderr" });
    process.exit(2);
  }

  const unidentifiable = compared.unidentifiable;
  if (unidentifiable.length > 0) {
    console.error("REFUSED: " + unidentifiable.length + " package(s) are installed and expose a package.json that does");
    console.error("  not declare a usable `name` or `version` string, so there is no identity to compare them by.");
    for (const u of unidentifiable) console.error("    " + u.name + " (pinned at " + u.want + "): " + u.why);
    console.error(notYourCode);
    console.error("\n  REMEDY: reinstall with `npm ci` in " + SELF_DIR + ", or read those fields another way.");
    console.error("\n  Exit 2 rather than 1: the tree may be perfectly correct. What is missing is the question, not");
    console.error("  the answer.");
    verdictSkipped(unidentifiable.length + " pinned package(s) declare no readable name or version, so the ajv pin could not be checked", { canonicalTo: "stderr" });
    process.exit(2);
  }

  const unreadable = compared.unreadable.map((u) => u.name + " (pinned at " + u.want + ")");
  const absent = compared.absent.map((a) => a.name + " " + a.want);
  const wrong = compared.wrong.map((w) => w.name + ": lockfile pins " + w.want + ", resolves to " + w.got);
  // THE FINDING THIS WHOLE COMMIT IS ABOUT. A lockfile key is a DIRECTORY PATH, and the version read out
  // of that directory is a fact about whatever package is sitting in it. Until nothing read
  // the installed `name`, so a directory named for the judge holding some other package at the version
  // the lockfile named passed, and the pass line said the judge "was compared and resolves at the version
  // the lockfile names".
  const misnamed = compared.misnamed.map(
    (m) => m.name + ": the lockfile pins " + m.name + " " + m.want + " at that directory, but the package installed there declares itself " + m.declared + " " + m.version
  );
  if (unreadable.length > 0) {
    console.error("REFUSED: " + unreadable.length + " package(s) are installed but will not expose their own");
    console.error("  package.json, so their version could not be read and this check has no opinion on them.");
    console.error("  The usual cause is an `exports` map that declines the ./package.json subpath.");
    for (const u of unreadable) console.error("    " + u);
    console.error(notYourCode);
    console.error("\n  REMEDY: read those versions another way rather than calling an installed package missing.");
    console.error("\n  Exit 2 rather than 1: the tree may be perfectly correct. Reporting these as absent would put");
    console.error("  a false red on a tree npm ci had just built exactly as the lockfile asked.");
    verdictSkipped(unreadable.length + " pinned package(s) would not expose package.json, so the ajv pin could not be checked", { canonicalTo: "stderr" });
    process.exit(2);
  }

  const failures = absent.length + wrong.length + misnamed.length;
  if (failures > 0) {
    console.error("FAIL: the installed npm tree does not match scripts/schema-validate/package-lock.json.");
    console.error(notYourCode);
    console.error("");
    console.error("  REMEDY: run `npm ci` in " + SELF_DIR);
    console.error("    or `make schema-validate` from the repository root, which does the same install and then");
    console.error("    runs this file. `npm ci` installs exactly what the lockfile says and never rewrites it.");
    console.error("");
    const lockAt = fs.existsSync(LOCK_PATH) ? fs.statSync(LOCK_PATH).mtime.toISOString() : null;
    const installedAt = fs.existsSync(INSTALL_RECORD) ? fs.statSync(INSTALL_RECORD).mtime.toISOString() : null;
    if (lockAt !== null && installedAt !== null) {
      console.error("  npm last installed here at    " + installedAt);
      console.error("  package-lock.json last written " + lockAt);
      if (Date.parse(lockAt) > Date.parse(installedAt)) {
        console.error("  The lock is NEWER than the install, so this is a tree that has not caught up rather than");
        console.error("  anything you changed.");
      }
      console.error("");
    }
    for (const a of absent) console.error("  NOT INSTALLED  " + a);
    for (const w of wrong) console.error("  WRONG VERSION  " + w);
    for (const m of misnamed) console.error("  NOT THAT PACKAGE  " + m);
    // Printed on the failing path as well as the passing one. A reader looking at a red run is entitled
    // to know what this check did NOT compare, and telling them only on green would mean the set-aside
    // list is read on exactly the days nobody needs it.
    for (const w of workspaces) console.error("  SET ASIDE      " + w + " (a workspace member, which npm links rather than fetches, so it is not a pin)");
    for (const l of linked) console.error("  SET ASIDE      " + l + " (npm's link record for a workspace member: link: true and no version, so it is not a pin)");
    for (const a of aliased) console.error("  SET ASIDE      " + a.key + " (npm's alias record: the entry declares the name " + a.declared + ", so that directory holds a different package)");
    console.error("  COMPARED       " + [...pinned.keys()].join(", "));
    console.error("");
    console.error("  Worth doing rather than working around: this lockfile moves when an npm advisory is cleared,");
    console.error("  so a tree behind it is running the versions the lock exists to escape. It moved on 2026-08-08");
    console.error("  to close four, three of them HIGH, in the production tree.");
    console.error("");
    console.error("  And the validation itself is not trustworthy until this is fixed: every result below is a");
    console.error("  claim about docs/format/schema.json made by a validator this repository did not pin.");
    verdictReached(failures, pinned.size, { canonicalTo: "stderr" });
    process.exit(1);
  }

  // THE PASS LINE LEADS WITH THE SUBJECT AND ITS VERSION, and that ordering is the repair rather than
  // decoration. The line it replaces was affirmative in both directions: it said all packages resolved,
  // that none was excluded and that no workspace member was named, all three true of every bucket it
  // mentioned, while the one package the file exists to pin had not been compared at all. A sentence
  // whose every clause is true and whose subject went ungraded is worse than one carrying a discrepancy,
  // because a discrepancy is something a reader can pull on.
  //
  // `compared.verified.get(JUDGE)` is the identity READ OFF THE COMPARISON, so this clause cannot be
  // printed unless the judge reached the one outcome where its installed name and version were both read
  // and both matched: it is not a restatement of the floor above, it is the same fact reaching the
  // reader. And the arithmetic is closed on the line rather than left implied, m of n keys, so a key that
  // went anywhere at all has somewhere to show up.
  const keyCount = Object.keys(lock.packages).length;
  const filed = pinned.size + excluded.length + linked.length + aliased.length + workspaces.length + roots.length;
  // Every other disposition has already refused by the time this line is reached, so the five remaining
  // buckets plus the root must exhaust the map. This arm caught the alias bucket being added on
  // and not counted here, which is the edit it was written for: the pass line states an
  // arithmetic, so the arithmetic is checked rather than asserted. selfTest drives the same identity.
  if (filed !== keyCount) {
    console.error("REFUSED: the classifier was given " + keyCount + " package key(s) and accounted for " + filed + ".");
    console.error("  " + (keyCount - filed) + " reached no disposition this line can print, so the pass line would have");
    console.error("  described a comparison narrower than it claimed. This is an internal inconsistency in the check.");
    console.error(notYourCode);
    verdictSkipped("the lockfile classifier did not account for every package key, so the pin result cannot be stated", { canonicalTo: "stderr" });
    process.exit(2);
  }

  const asides = [];
  if (excluded.length > 0) {
    asides.push(excluded.length + " excluded as optional or platform-gated (" + excluded.join(", ") + ")");
  }
  if (linked.length > 0) {
    asides.push(linked.length + " npm link record(s) carrying no version because nothing was fetched (" + linked.join(", ") + ")");
  }
  if (workspaces.length > 0) {
    asides.push(workspaces.length + " workspace member(s), which npm links rather than fetches so they are not pins (" + workspaces.join(", ") + ")");
  }
  if (aliased.length > 0) {
    asides.push(
      aliased.length + " npm alias record(s), where the lockfile's own entry declares another package's name for that directory (" + aliased.map((a) => a.key + " -> " + a.declared).join(", ") + ")"
    );
  }
  if (roots.length > 0) {
    asides.push(roots.length + " root entry, which is this project rather than a dependency");
  }

  // THE SECOND HALF OF THE FLOOR, and it is the half the fourth generation did not have. The floor above
  // asks the LOCKFILE about the judge. This one asks the INSTALLED TREE, and it can only be satisfied by
  // an outcome that read the installed package's own `name`. It is unreachable today, because a judge
  // that reached any other outcome has already exited above, and it is here so that it stays unreachable:
  // an edit that adds an outcome and routes the judge into it exits 2 here rather than printing a pass
  // line about a package nothing identified.
  const judgeIdentity = compared.verified.get(JUDGE);
  if (judgeIdentity === undefined) {
    console.error("REFUSED: " + JUDGE + " reached no outcome that read its installed name and version, so the pin");
    console.error("  line below would have named a package this run never identified.");
    console.error(notYourCode);
    verdictSkipped(JUDGE + " was not identified in the installed tree, so the validator pin could not be checked", { canonicalTo: "stderr" });
    process.exit(2);
  }

  // AND THE MODULE main() LOADS IS TIED TO THE PACKAGE THAT WAS GRADED. Until now two independent
  // resolutions ran and nothing connected them: this check resolved `ajv/package.json` and main()
  // resolved `ajv/dist/2020.js`, so a tree where those two land in different directories was graded on
  // one and run on the other. The containment test is the link, and it is taken on realpaths so a
  // symlinked package directory, which is what npm workspaces and pnpm both write, is not a false red.
  const within = judgeModuleWithinGradedPackage();
  if (within !== null) {
    console.error("FAIL: the module this file loads is not inside the package this check graded.");
    console.error("  " + within);
    console.error(notYourCode);
    console.error("\n  REMEDY: run `npm ci` in " + SELF_DIR + ". A tree where `" + AJV_MODULE + "` resolves outside");
    console.error("  the " + JUDGE + " package directory is not the tree the lockfile describes.");
    verdictReached(1, pinned.size, { canonicalTo: "stderr" });
    process.exit(1);
  }

  // AND THE SAME CONTAINMENT FOR THE OTHER FOUR PINS. See entryContainment: until this line the judge was
  // the only package whose code location was checked at all, and a `main` field is not a `name` and is not
  // a `version`, so a pinned package could point its entry out of the tree and still be printed as
  // compared. The verified set is used rather than the pinned set because a package that failed to
  // identify itself has already exited above.
  const entries = entryContainment([...compared.verified.keys()], resolveEntryOnDisk);
  const entriesFiled = entries.contained.length + entries.outside.length + entries.noEntry.length + entries.unresolvable.length;
  if (entriesFiled !== compared.verified.size) {
    console.error("REFUSED: " + compared.verified.size + " verified package(s) were handed to the entry containment test");
    console.error("  and " + entriesFiled + " came back with an outcome. " + (compared.verified.size - entriesFiled) + " reached none, so this check");
    console.error("  cannot say where their code lives. This is an internal inconsistency in the check.");
    console.error(notYourCode);
    verdictSkipped("the entry containment test did not account for every verified package", { canonicalTo: "stderr" });
    process.exit(2);
  }
  if (entries.unresolvable.length > 0) {
    console.error("REFUSED: " + entries.unresolvable.length + " pinned package(s) have a package.json that resolves but no");
    console.error("  entry that does, so where their code lives could not be read.");
    for (const u of entries.unresolvable) console.error("    " + u.name + ": " + u.why);
    console.error(notYourCode);
    console.error("\n  REMEDY: run `npm ci` in " + SELF_DIR + ".");
    verdictSkipped("a pinned package's entry point could not be resolved, so its containment could not be checked", { canonicalTo: "stderr" });
    process.exit(2);
  }
  if (entries.outside.length > 0) {
    console.error("FAIL: " + entries.outside.length + " pinned package(s) load their code from outside their own directory.");
    for (const o of entries.outside) {
      console.error("  " + o.name + " resolves to " + o.entry + ", which is outside the graded package directory " + o.dir);
    }
    console.error(notYourCode);
    console.error("\n  REMEDY: run `npm ci` in " + SELF_DIR + ". A tree where a pinned package's entry point resolves");
    console.error("  outside its own package directory is not the tree the lockfile describes: the name and the version");
    console.error("  the comparison above read still belong to the package, and the code does not.");
    verdictReached(entries.outside.length, pinned.size, { canonicalTo: "stderr" });
    process.exit(1);
  }

  console.log(
    "validator pinned: the package node resolves for " +
      JSON.stringify(JUDGE) +
      " declares itself " +
      judgeIdentity.name +
      " " +
      judgeIdentity.version +
      ", which is the name and the version package-lock.json puts at that directory, and " +
      JSON.stringify(AJV_MODULE) +
      " resolves inside that same package directory. " +
      compared.verified.size +
      " of the lockfile's " +
      keyCount +
      " package key(s) were compared by name and version (" +
      [...compared.verified.keys()].join(", ") +
      "); the remaining " +
      (keyCount - compared.verified.size) +
      (keyCount - compared.verified.size === 1 ? " is " : " are ") +
      (asides.length === 0 ? "none" : asides.join(", and ")) +
      "."
  );
  console.log(
    "  entry containment: all " +
      entries.contained.length +
      " of those package(s) resolve their own entry point inside their own package directory" +
      (entries.noEntry.length === 0 ? "" : ", and " + entries.noEntry.length + " expose no bare entry to contain (" + entries.noEntry.map((n) => n.name).join(", ") + ")") +
      "."
  );

  // WHAT THIS DOES NOT CLAIM, printed rather than left to a comment, because the lines above read like an
  // identity claim and they are not quite one. THE PREVIOUS VERSION OF THIS SENTENCE WAS NARROWER THAN
  // THE HOLE IT DISCLOSED. It said a file inside the graded directory could re-export another package.
  // Two escapes measured ran code that was not inside the graded directory and not inside
  // node_modules at all, one through `main` and one through a single `require` climbing out of the tree,
  // both exit 0 at 112 checks. Both are now checked, the first before anything loads and the second by
  // reading what the process actually loaded, so this sentence is about what genuinely remains.
  //
  // THE BYTES ARE THE RESIDUAL, AND THEY ARE NOT CHECKABLE FROM HERE. package-lock.json carries a sha512
  // `integrity` for each of these packages and this file reads none of them, which looks like an omission
  // and is not. MEASURED rather than recalled: fetching fast-uri-3.1.5.tgz from the registry
  // and hashing it reproduces the lockfile's integrity string byte for byte, so that digest is over the
  // REGISTRY TARBALL and not over the extracted directory; and `npm pack` of the installed directory
  // produces the same file list and a DIFFERENT digest, because a tarball hash covers tar and gzip
  // framing that extraction does not preserve. So the installed tree cannot reproduce the digest the
  // lockfile carries, and a check here claiming to verify integrity would be verifying something else.
  //
  // THE THING THAT DOES VERIFY THOSE BYTES IS `npm ci`, which fetches each tarball and checks it against
  // exactly this digest before extracting. Both callers that read node_modules run it immediately first:
  // `make schema-validate` and the CI job Schema (ajv vectors) are each `npm ci && npm run validate`.
  // Running `npm run validate` on its own against a tree nobody has just installed gets no byte check,
  // and that is stated here rather than papered over.
  console.log(
    "  scope of that claim: the names, the versions, the entry-point locations and the modules this " +
      "process actually loaded were read. The BYTES of those files were not: the lockfile's sha512 is a " +
      "digest of the registry tarball, which an installed tree cannot reproduce, and `npm ci` is what " +
      "checks it. So a run started without a fresh `npm ci` says nothing about file contents."
  );

  // The realpath'd directory of every package that was graded, for the load census in main(). It is taken
  // from the same resolution that was graded rather than rebuilt from the names, so the census cannot end
  // up describing a different set of directories from the one the pass line above just described.
  return entries.contained.map((c) => path.dirname(fs.realpathSync(requireHere.resolve(c.name + SEP + "package.json"))));
}

// realTree is the filesystem half, kept apart from surveyVectors for the same reason probeInstalled is
// kept apart from compareInstalled: the rule can then be driven over corpora that do not exist on disk.
// Each method answers ONE question and answers it about the path it was given, so "absent" and "present
// but the wrong kind of thing" never collapse into one answer.
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

// surveyVectors REPORTS THE WHOLE CORPUS rather than returning what it found. That is the difference
// between this and the two listers it replaces, and it is the difference the finding was about: a lister
// that returns its hits cannot be asked what it passed over, so nothing downstream can tell an empty
// corpus from an empty answer.
//
// Every entry the vectors directory holds leaves through exactly one bucket, and every vector carries
// its own emptiness as DATA rather than as an absence: the state of its run directory, the run
// directories that yielded no manifest, and whether the RUNLOG is there. The one `continue` below files
// first and continues afterwards, which is what makes it a placement rather than the drop this function
// exists to remove.
//
// PURE, given a tree. It takes no decision about whether an empty vector is allowed; auditVectorCoverage
// does that, over this output, so the survey cannot quietly agree with the policy it is measured by.
function surveyVectors(tree) {
  const names = tree.listDir(VECTORS_DIR);
  if (names === null) return null;
  const vectors = [];
  const notDirectories = [];
  for (const name of [...names].sort()) {
    const vecDir = path.join(VECTORS_DIR, name);
    if (!tree.isDirectory(vecDir)) {
      // FILED, NOT SKIPPED, exactly as the lockfile's root key is. An entry that is not a directory is
      // not a vector, and saying so by putting it in a bucket is what lets the caller check that every
      // entry the directory holds was accounted for. It carries WHY it is not a vector for the same
      // reason the two axes below do: a declaration names a cause, and a cause nothing reports cannot
      // be held to.
      notDirectories.push({
        name,
        cause: tree.isFile(vecDir) ? "a file" : "there, and neither a file nor a directory",
      });
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
      // THREE DISTINCT INPUTS, REPORTED AS THREE, because the refusal below prints this string and
      // "absent" is a different thing for a reader to go and check than "there but unreadable".
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
    // WHAT IS BESIDE THE ABSENT LOG, and it is here because the RUNLOG axis has two declared vectors
    // whose emptiness is the SAME state for OPPOSITE reasons. absent-runlog is a negative vector whose
    // whole defect is a deleted RUNLOG with its signature left in place; the four known-answer vectors
    // have no archive at all. Both report "absent", so absent on its own cannot tell a deliberate hole
    // from an archive that went missing, and a declaration checked only against "absent" goes on being
    // satisfied through that change.
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
      // THE TWO CAUSES, one per axis, each a single string a declaration can be compared with. The
      // manifest axis needs no composing: the run directory's state IS why the vector yields nothing.
      manifestCause: runDirState,
      runlogCause: runlogState + ", and " + runlogSibling,
    });
  }
  return { entries: names.length, vectors, notDirectories };
}

// auditVectorCoverage decides, over a survey and the declaration tables above, which silences were
// declared. It returns rather than exits, so `--self-test` drives the shipped rule over fabricated
// corpora and the same function makes the decision in both places.
//
// TWO OUTCOMES AND THEY ARE NOT THE SAME OUTCOME. A refusal is an undeclared empty: this run cannot say
// whether that vector conforms, so it must not report a pass, and exit 2 is what this file uses for
// could-not-check. A finding is a declaration the corpus no longer bears out: nothing went ungraded, so
// exit 1 with a remedy is right, and letting it pass would leave a list that only ever grows.
//
// THE DENOMINATOR IS READ OFF THE INPUT. `entries` is the length of the directory listing, taken before
// any rule ran, so the totality identity below is not a restatement of any rule here and holds for any
// correct survey whatever its buckets.
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
      "the vectors directory holds " +
        survey.entries +
        " entry/entries and the survey filed " +
        filed +
        ". " +
        (survey.entries - filed) +
        " reached no bucket, so this check cannot say what it saw for them"
    );
  }

  // THE THIRD DIRECTION, applied at every declared site by one rule rather than four. A declaration is
  // satisfied only if the silence it permits is STILL THERE FOR THE CAUSE IT NAMES. `observed` comes
  // from the survey, `decl.cause` from the table, and they are compared string for string.
  //
  // A MISMATCH IS A FINDING AND NOT A REFUSAL, for the reason the stale sweep is: something IS known.
  // The vector is still empty and this file still says it may be, so nothing went ungraded; what has
  // happened is that the tree stopped agreeing with the reason on the line. That is a one-line remedy,
  // and exit 1 is what says so.
  //
  // A DECLARATION WITH NO CAUSE REFUSES. It is a blanket exemption wearing a reason, and it cannot be
  // held to any of the three directions, so this run cannot say whether that silence is still the one
  // that was granted.
  const causeHolds = (table, key, observed, site) => {
    const decl = table[key];
    if (typeof decl?.cause !== "string" || decl.cause.length === 0) {
      refusals.push(
        site + " declares " + JSON.stringify(key) + " and names no cause, so nothing can say whether the silence it permits is still the silence that was granted"
      );
      return;
    }
    if (decl.cause !== observed) {
      findings.push(
        site +
          " declares " +
          JSON.stringify(key) +
          " because " +
          JSON.stringify(decl.cause) +
          ", and it is now " +
          JSON.stringify(observed) +
          ". The silence is still there and its cause is not, so the exemption is being applied to something it was not granted for"
      );
    }
  };

  for (const entry of survey.notDirectories) {
    if (Object.prototype.hasOwnProperty.call(tables.notAVector, entry.name)) {
      usedNotAVector.add(entry.name);
      causeHolds(tables.notAVector, entry.name, entry.cause, "NOT_A_VECTOR");
      continue;
    }
    refusals.push(
      JSON.stringify(entry.name) +
        " sits beside the vector directories and is not a directory, so it is not a vector this check can" +
        " read and it is not declared in NOT_A_VECTOR either"
    );
  }

  let yieldsManifest = 0;
  let yieldsRunlog = 0;
  // COUNTED IN THE BRANCH, NEVER RECOMPUTED AFTERWARDS. This file's own header records the shape: a
  // totality assertion that recomputes one of its terms with the predicate that produced it balances by
  // construction and cannot see the case it exists for. So each arm increments as it is taken, and the
  // identity below adds up what the loop DID rather than what it should have done.
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
      refusals.push(
        "vector " +
          JSON.stringify(v.vector) +
          " yields no root manifest (" +
          v.runDirState +
          ") and is not declared in EXPECT_NO_ROOT_MANIFEST"
      );
    }

    if (v.runlog !== null) {
      yieldsRunlog += 1;
    } else if (Object.prototype.hasOwnProperty.call(tables.noRunlog, v.vector)) {
      usedNoRunlog.add(v.vector);
      declaredEmptyRunlogs.push(v.vector);
      causeHolds(tables.noRunlog, v.vector, v.runlogCause, "EXPECT_NO_RUNLOG");
    } else {
      undeclaredEmptyRunlogs += 1;
      refusals.push(
        "vector " +
          JSON.stringify(v.vector) +
          " yields no RUNLOG (" +
          v.runlogState +
          ") and is not declared in EXPECT_NO_RUNLOG"
      );
    }

    for (const r of v.runsWithoutManifest) {
      const key = r.vector + SEP + r.runId;
      if (Object.prototype.hasOwnProperty.call(tables.runWithoutRootManifest, key)) {
        usedRunWithout.add(key);
        causeHolds(tables.runWithoutRootManifest, key, r.why, "EXPECT_RUN_WITHOUT_ROOT_MANIFEST");
        continue;
      }
      refusals.push(
        "run directory " + JSON.stringify(key) + " yields no root manifest (" + r.why + ") and is not declared in EXPECT_RUN_WITHOUT_ROOT_MANIFEST"
      );
    }
  }

  // THE ARITHMETIC CLOSES ON THE POLICY, one axis at a time. Every vector either yielded a manifest, was
  // declared to yield none, or was refused; likewise for its RUNLOG. Both terms are tallies the loop
  // above kept, and the denominator is the vector count read off the survey, so a future edit that adds
  // a fourth path and forgets to file it comes back here rather than passing as a vector nobody graded.
  //
  // AND IT IS A BACKSTOP RATHER THAN A PINNED CHECK, which is worth saying because an assertion nobody
  // can kill reads exactly like one the tests hold down. MEASURED: injecting the shape
  // this exists for, a `continue` upstream of both arms, is caught with these two lines present AND
  // with both of them disabled, because the same fixture's refusal count and stale-declaration sweep
  // already catch it. Disabling these two lines alone leaves the self-test at 0 failures. They are here
  // for the edit that has not been written yet, not because a fixture requires them.
  const manifestAxis = yieldsManifest + declaredEmptyManifests.length + undeclaredEmptyManifests;
  const runlogAxis = yieldsRunlog + declaredEmptyRunlogs.length + undeclaredEmptyRunlogs;
  if (manifestAxis !== survey.vectors.length) {
    refusals.push("the manifest axis accounted for " + manifestAxis + " of " + survey.vectors.length + " vector(s)");
  }
  if (runlogAxis !== survey.vectors.length) {
    refusals.push("the RUNLOG axis accounted for " + runlogAxis + " of " + survey.vectors.length + " vector(s)");
  }

  // THE OTHER DIRECTION, so the tables cannot rot into a place names are parked. A declaration the corpus
  // does not bear out is a finding with a one-line remedy, and it is a finding rather than a refusal
  // because something IS known: this file says a vector is empty and the vector is not.
  const present = new Map(survey.vectors.map((v) => [v.vector, v]));
  for (const name of Object.keys(tables.noRootManifest)) {
    if (usedNoManifest.has(name)) continue;
    findings.push(
      "EXPECT_NO_ROOT_MANIFEST declares " +
        JSON.stringify(name) +
        " yields no root manifest, and " +
        (present.has(name) ? "it yields " + present.get(name).manifests.length : "there is no such vector directory")
    );
  }
  for (const name of Object.keys(tables.noRunlog)) {
    if (usedNoRunlog.has(name)) continue;
    findings.push(
      "EXPECT_NO_RUNLOG declares " +
        JSON.stringify(name) +
        " yields no RUNLOG, and " +
        (present.has(name) ? "it has one at " + rel(present.get(name).runlog) : "there is no such vector directory")
    );
  }
  for (const key of Object.keys(tables.runWithoutRootManifest)) {
    if (usedRunWithout.has(key)) continue;
    findings.push("EXPECT_RUN_WITHOUT_ROOT_MANIFEST declares " + JSON.stringify(key) + ", and no such run directory came back empty");
  }
  for (const name of Object.keys(tables.notAVector)) {
    if (usedNotAVector.has(name)) continue;
    findings.push(
      "NOT_A_VECTOR declares " +
        JSON.stringify(name) +
        ", and it is " +
        (present.has(name) ? "a vector directory" : "not there at all")
    );
  }

  return { refusals, findings, declaredEmptyManifests, declaredEmptyRunlogs, yieldsManifest, yieldsRunlog };
}

const DECLARED_EMPTY = {
  noRootManifest: EXPECT_NO_ROOT_MANIFEST,
  noRunlog: EXPECT_NO_RUNLOG,
  runWithoutRootManifest: EXPECT_RUN_WITHOUT_ROOT_MANIFEST,
  notAVector: NOT_A_VECTOR,
};

// requireDeclaredCoverage is the only place the audit turns into an exit code. It runs BEFORE a single
// manifest is validated, for the same reason requirePinnedValidator does: a run that is going to refuse
// should refuse before it prints 111 lines of `ok` that invite the reader to stop there.
function requireDeclaredCoverage(survey) {
  const audit = auditVectorCoverage(survey, DECLARED_EMPTY);

  if (audit.refusals.length > 0) {
    console.error("REFUSED: " + audit.refusals.length + " part(s) of the conformance corpus came back empty");
    console.error("  and nothing in this file says they are allowed to. A vector that yields no object and a");
    console.error("  vector that passed read the same on the exit code, so this declines rather than pass.");
    for (const r of audit.refusals) console.error("    " + r);
    console.error("\n  REMEDY: if the corpus is incomplete, restore it with");
    console.error("  `go test ./internal/format -run TestConformance -update`. If a vector is MEANT to yield");
    console.error("  nothing, declare it in EXPECT_NO_ROOT_MANIFEST, EXPECT_NO_RUNLOG or");
    console.error("  EXPECT_RUN_WITHOUT_ROOT_MANIFEST with the reason and the SPEC.md rule, as the four");
    console.error("  known-answer vectors and absent-runlog are. Do not widen a table to a pattern.");
    console.error("\n  Exit 2 rather than 1: nothing is known to be wrong with those vectors. What is not known");
    console.error("  is whether they conform, because nothing of theirs was put through the schema.");
    verdictSkipped("part of the conformance corpus yielded no object and was not declared as allowed to", { canonicalTo: "stderr" });
    process.exit(2);
  }

  if (audit.findings.length > 0) {
    console.error("FAIL: " + audit.findings.length + " declaration(s) in this file no longer describe the corpus:");
    for (const f of audit.findings) console.error("  - " + f);
    console.error("\n  REMEDY: delete the line. These tables exist to name the silences that are intended, so a");
    console.error("  line that names no silence is one nobody is checking and one the next reader will trust.");
    verdictReached(audit.findings.length, survey.vectors.length);
    process.exit(1);
  }

  console.log(
    "corpus surveyed: " +
      survey.vectors.length +
      " vector(s) and " +
      survey.notDirectories.length +
      " declared non-vector entry/entries account for all " +
      survey.entries +
      " entries under " +
      rel(VECTORS_DIR) +
      ". " +
      audit.yieldsManifest +
      " yield a root manifest and " +
      audit.yieldsRunlog +
      " a RUNLOG; the rest are DECLARED empty, which is " +
      (audit.declaredEmptyManifests.length === 0 ? "no vector" : audit.declaredEmptyManifests.join(", ")) +
      " for the manifest and " +
      (audit.declaredEmptyRunlogs.length === 0 ? "no vector" : audit.declaredEmptyRunlogs.join(", ")) +
      " for the RUNLOG. An undeclared empty is a refusal at exit 2, not a pass."
  );
  return audit;
}

function rel(p) {
  return path.relative(REPO_ROOT, p);
}

// `node validate.mjs --self-test` proves the lockfile classifier puts each shape in the right bucket,
// offline, with no install and no vector read. It exists because the shape it is mostly about, a
// workspace key, cannot be exercised by this repository's own lockfile: there is no workspace here and
// there should not be one, so without fixtures the arm would ship untested and be discovered the day a
// lockfile grows one.
//
// IT DRIVES THE SHIPPED FUNCTION. Every case below calls classifyLockPackages, the same function
// requirePinnedValidator calls, rather than restating its rules. A control that re-implements what it
// checks exercises nothing and therefore agrees with everything.
//
// AND IT CARRIES TWO KNOWN-POSITIVE CONTROLS, ONE PER GENERATION IT SUPERSEDES, because a control that
// does not match the scheme it checks is a zero that merely looks checked.
//
// supersededByOffset  the rule shipped until morning. It searched the key for the
//                       substring `node_modules/` and branched on the offset, so a separator, a scope
//                       and a directory whose name merely ends in the sentinel were one answer.
// supersededByDrop    the rule shipped until evening. It parsed the key into segments,
//                       which fixed all of that, and it still dropped an entry it could not read
//                       BEFORE the classifier ran, on `typeof entry?.version !== "string"`.
//
// Both are the old bodies rather than descriptions of them, so their defects are present rather than
// paraphrased. Every assertion below is required to FAIL on the generation it is about, and the case
// table records what each generation reaches, so a case whose three answers are the same is visibly a
// case that cannot tell the rules apart.
//
// THE PREVIOUS TOTALITY ASSERTION WAS MEASURED WITH THE RULE UNDER TEST, which is the defect one level
// up from the one it was written to replace. It asserted filed === versioned, and it computed
// `versioned` as `cases.filter((c) => c.key !== "" && typeof c.entry.version === "string").length`,
// which is the dropped guard clause restated. A key the rule dropped was subtracted from the
// denominator by the same predicate that dropped it, so the arithmetic balanced by construction and
// could not see the drop however many keys it swallowed.
//
// WHAT REPLACES IT READS THE DENOMINATOR OFF THE INPUT: the classifier was handed n keys, so n keys
// must come back filed, counting the root. That identity is not a restatement of any rule, it holds for
// any correct classifier whatever its buckets, and supersededByDrop violates it on every dropped key.
//
// AND dispositionOf HAS NO DEFAULT ARM. It used to end in an unconditional `return "skipped"`, which is
// the same shape as the `else` that let the second generation call itself total: a key that landed in no
// bucket at all was reported as the disposition of having been deliberately skipped, and a case wanting
// `skipped` passed whether the rule had decided anything or not. Each disposition is now a checked
// predicate over the classifier's own output, a result matching none of them comes back UNPLACED, and
// UNPLACED is not a disposition any case may want. That is what turns the drop from an expectation into
// a failure: the cases the old rules dropped now record `UNPLACED` against those rules by name.
function selfTest() {
  // GENERATION 2, verbatim: the rule as it stood before the key was parsed rather than searched.
  function supersededByOffset(packages) {
    const pinned = new Map();
    const excluded = [];
    const nested = [];
    const workspaces = [];
    for (const [key, entry] of Object.entries(packages ?? {})) {
      if (key === "" || typeof entry?.version !== "string") continue;
      const at = key.indexOf("node_modules/");
      if (at === -1) {
        workspaces.push(key);
        continue;
      }
      if (entry.optional === true || entry.os !== undefined || entry.cpu !== undefined) {
        excluded.push(at === 0 ? key.slice("node_modules/".length) : key);
        continue;
      }
      if (at !== 0 || key.indexOf("node_modules/", "node_modules/".length) !== -1) {
        nested.push(key);
        continue;
      }
      pinned.set(key.slice("node_modules/".length), entry.version);
    }
    return { pinned, excluded, nested, workspaces, unmodelled: [] };
  }

  // GENERATION 3, verbatim: segments rather than an offset, and still the guard clause upstream of every
  // bucket. It calls the SHIPPED classifyKey, which is correct and is not what this control is about:
  // what it reproduces is the drop, which happened before classifyKey was ever reached.
  function supersededByDrop(packages) {
    const pinned = new Map();
    const excluded = [];
    const nested = [];
    const workspaces = [];
    const unmodelled = [];
    for (const [key, entry] of Object.entries(packages ?? {})) {
      if (key === "" || typeof entry?.version !== "string") continue;
      const at = classifyKey(key);
      if (at.where === "unmodelled") {
        unmodelled.push({ key, why: at.why });
        continue;
      }
      if (at.where === "nested") {
        nested.push(key);
        continue;
      }
      if (at.where === "workspace") {
        workspaces.push(key);
        continue;
      }
      if (entry.optional === true || entry.os !== undefined || entry.cpu !== undefined) {
        excluded.push(at.name);
        continue;
      }
      pinned.set(at.name, entry.version);
    }
    return { pinned, excluded, nested, workspaces, unmodelled };
  }

  // Where a single key landed, read off a classifier's own outputs. It looks the key up rather than
  // deriving a name from it, because deriving a bare name is the very step the rules disagree about and a
  // probe that derived it would be reading with the rule it is grading. The name-keyed buckets are driven
  // one key at a time, so for them the checked predicate is that the bucket holds exactly one thing.
  //
  // NO DEFAULT ARM. Every disposition is entered on a predicate that was checked. A key matching none
  // comes back UNPLACED and a key matching more than one comes back AMBIGUOUS, and neither is a
  // disposition a case may want: both are reports that the classifier did not place it.
  const dispositionOf = (result, key) => {
    const found = [];
    if ((result.roots ?? []).includes(key)) found.push("root");
    if (result.workspaces.includes(key)) found.push("workspace");
    if (result.nested.includes(key)) found.push("nested");
    if ((result.unmodelled ?? []).some((u) => u.key === key)) found.push("unmodelled");
    if ((result.unreadable ?? []).some((u) => u.key === key)) found.push("unreadable");
    if ((result.aliased ?? []).some((a) => a.key === key)) found.push("aliased");
    if ((result.linked ?? []).length === 1) found.push("linked");
    if (result.pinned.size === 1) found.push("pinned");
    if (result.excluded.length === 1) found.push("excluded");
    if (found.length === 1) return found[0];
    if (found.length === 0) return "UNPLACED";
    return "AMBIGUOUS(" + found.join("+") + ")";
  };

  // Each bucket's defining property, asserted over a classifier's OUTPUT, plus the totality identity
  // taken against the INPUT it was given. Returns the violations, so the same function serves as the
  // assertion for the shipped rule and as the positive control against both superseded ones.
  const bucketViolations = (result, packages) => {
    const bad = [];
    const isName = (n) => {
      if (typeof n !== "string" || n.includes("\\")) return false;
      const p = n.split(SEP);
      if (p.some((s) => s === "" || s === NM_SEG)) return false;
      return (p.length === 1 && !p[0].startsWith("@")) || (p.length === 2 && p[0].startsWith("@"));
    };
    for (const k of result.workspaces) {
      if (k.includes("\\")) bad.push("workspace " + JSON.stringify(k) + " carries a backslash, so it is not a path npm wrote");
      if (k.split(SEP).includes(NM_SEG)) bad.push("workspace " + JSON.stringify(k) + " contains a node_modules segment, so it is an install location and not a repository path");
    }
    for (const k of result.nested) {
      const segs = k.split(SEP);
      const first = segs.indexOf(NM_SEG);
      const last = segs.lastIndexOf(NM_SEG);
      if (first === -1) bad.push("nested " + JSON.stringify(k) + " contains no node_modules segment at all, so nothing about it is nested");
      else if (first === 0 && last === 0 && last !== segs.length - 1) bad.push("nested " + JSON.stringify(k) + " has exactly one leading node_modules segment, which is a top-level install");
    }
    for (const n of result.pinned.keys()) if (!isName(n)) bad.push("pinned name " + JSON.stringify(n) + " is not a shape npm can install");
    for (const n of result.excluded) if (!isName(n)) bad.push("excluded name " + JSON.stringify(n) + " is not a shape npm can install");
    for (const n of result.linked ?? []) if (!isName(n)) bad.push("linked name " + JSON.stringify(n) + " is not a shape npm can install");
    for (const u of result.unreadable ?? []) {
      if (typeof u.why !== "string" || u.why.length === 0) bad.push("unreadable " + JSON.stringify(u.key) + " carries no reason, and the refusal prints the reason");
    }
    // AN ALIAS RECORD'S DEFINING PROPERTY, read off the INPUT: the entry declares a `name` string that
    // is not the name its key carries. An entry whose declared name equals the key's name is not an
    // alias, and filing it as one would set aside a real pin on the strength of a redundant field.
    for (const a of result.aliased ?? []) {
      const entry = (packages ?? {})[a.key];
      if (typeof entry?.name !== "string") bad.push("aliased " + JSON.stringify(a.key) + " has no `name` string in its entry, so nothing said the directory holds another package");
      else if (entry.name === a.name) bad.push("aliased " + JSON.stringify(a.key) + " declares the name its own key carries, which is not an alias");
      else if (entry.name !== a.declared) bad.push("aliased " + JSON.stringify(a.key) + " was recorded as declaring " + JSON.stringify(a.declared) + " but its entry declares " + JSON.stringify(entry.name));
      if (!isName(a.name)) bad.push("aliased key name " + JSON.stringify(a.name) + " is not a shape npm can install");
    }
    // A pinned entry must carry the version its entry declared, not merely a name. Read off the input, so
    // a classifier that filed every key correctly and carried the wrong version is caught here.
    for (const [name, got] of result.pinned) {
      const src = Object.entries(packages).find(([k]) => k === NM + name || k.endsWith(SEP + name));
      if (src !== undefined && typeof src[1]?.version === "string" && src[1].version !== got) {
        bad.push("pinned " + JSON.stringify(name) + " carries version " + JSON.stringify(got) + " but its entry declares " + JSON.stringify(src[1].version));
      }
    }
    // TOTALITY, TAKEN AGAINST THE INPUT. The denominator is the number of keys the classifier was handed,
    // which is not a restatement of any rule and cannot be shrunk by the rule dropping a key.
    const byKey = new Set([
      ...(result.roots ?? []),
      ...result.workspaces,
      ...result.nested,
      ...(result.unmodelled ?? []).map((u) => u.key),
      ...(result.unreadable ?? []).map((u) => u.key),
      ...(result.aliased ?? []).map((a) => a.key),
    ]);
    const filed = byKey.size + result.pinned.size + result.excluded.length + (result.linked ?? []).length;
    const given = Object.keys(packages ?? {}).length;
    if (filed !== given) {
      bad.push(
        "the classifier was given " + given + " key(s) and filed " + filed + ": " + (given - filed) + " reached no bucket at all, so nothing downstream can name them and no count can miss them"
      );
    }
    return bad;
  };

  // `want` is the disposition the SHIPPED rule must reach. `offset` and `drop` are the dispositions the
  // two superseded rules reach, written down rather than derived so that a case whose answers are all the
  // same is visibly a case that cannot tell the rules apart. UNPLACED means the rule filed the key
  // nowhere at all, which is what a drop looks like from outside.
  const cases = [
    { key: "", entry: { name: "root", version: "0.0.0" }, want: "root", offset: "UNPLACED", drop: "UNPLACED", why: "the lockfile's own root entry is this project, not a dependency, so it is filed and counted rather than dropped" },
    { key: "node_modules/ajv", entry: { version: "8.20.0" }, want: "pinned", offset: "pinned", drop: "pinned", why: "a top-level install is the ordinary case and is compared" },
    { key: "node_modules/@scope/pkg", entry: { version: "1.2.3" }, want: "pinned", offset: "pinned", drop: "pinned", why: "a scoped name carries a slash of its own and is still top-level" },
    { key: "node_modules/fsevents", entry: { version: "2.3.3", optional: true }, want: "excluded", offset: "excluded", drop: "excluded", why: "npm is entitled not to install an optional entry" },
    { key: "node_modules/win-only", entry: { version: "1.0.0", os: ["win32"] }, want: "excluded", offset: "excluded", drop: "excluded", why: "npm is entitled not to install a platform-gated entry" },
    { key: "node_modules/ajv/node_modules/fast-uri", entry: { version: "3.0.0" }, want: "nested", offset: "nested", drop: "nested", why: "a nested copy would resolve to the top-level package of the same name, so it is refused" },
    { key: "node_modules/@scope/a/node_modules/b", entry: { version: "1.0.0" }, want: "nested", offset: "nested", drop: "nested", why: "a nested copy under a scoped parent is still nested" },
    { key: "packages/vectors-tool/node_modules/left-pad", entry: { version: "1.3.0" }, want: "nested", offset: "nested", drop: "nested", why: "a nested copy under a long workspace path was already refused, and still is" },
    { key: "packages/vectors-tool", entry: { name: "@downpipe/vectors-tool", version: "1.0.0" }, want: "workspace", offset: "workspace", drop: "workspace", why: "a workspace member is linked rather than fetched, so it is not a pin and nothing resolves its path" },
    { key: "pkgs/a/node_modules/left-pad", entry: { version: "1.3.0" }, want: "nested", offset: "nested", drop: "nested", why: "a nested copy under a workspace path shorter than node_modules/ is still nested" },
    { key: "node_modules/@scope/opt", entry: { version: "1.0.0", optional: true }, want: "excluded", offset: "excluded", drop: "excluded", why: "an excluded name is printed, so a scoped one must survive classification whole" },

    // THE FOUR GENERATION 3 WAS ABOUT, each measured against the real validator morning.
    { key: "node_modules\\ajv", entry: { version: "0.0.0-not-installed" }, want: "unmodelled", offset: "workspace", drop: "unmodelled", why: "a backslash is not the separator npm writes, so the offset rule found no node_modules and set the one real pin aside as a workspace member: exit 0, PASS, ajv never compared" },
    { key: "packages/my-node_modules/lib", entry: { version: "1.0.0" }, want: "workspace", offset: "nested", drop: "workspace", why: "a directory whose name merely ENDS IN the sentinel is not a node_modules, and the offset rule refused at exit 2 a member it could have set aside" },
    { key: "node_modules/@node_modules/foo", entry: { version: "1.0.0" }, want: "pinned", offset: "nested", drop: "pinned", why: "a SCOPE named @node_modules is not a nesting, and the offset rule refused at exit 2 an install it could have compared" },
    { key: "node_modules/ajv/node_modules/fast-deep-equal", entry: { version: "3.1.3", optional: true }, want: "nested", offset: "excluded", drop: "nested", why: "placement is decided before the exclusion, so marking a nested entry optional no longer disarms the tripwire" },

    // Three more shapes the segment rule answers and the offset rule answered wrongly or by luck.
    { key: "node_modules", entry: { version: "1.0.0" }, want: "unmodelled", offset: "workspace", drop: "unmodelled", why: "a node_modules directory naming no package inside it is not a repository path either" },
    { key: "node_modules/node_modules", entry: { version: "1.0.0" }, want: "unmodelled", offset: "pinned", drop: "unmodelled", why: "npm forbids `node_modules` as a package name, so this key names an install location with nothing in it rather than a package the offset rule would have gone looking for" },
    { key: "node_modules/a/b/c", entry: { version: "1.0.0" }, want: "unmodelled", offset: "pinned", drop: "unmodelled", why: "three unscoped name segments are not a package npm could have installed, and the offset rule pinned `a/b/c` and would have reported it NOT INSTALLED" },

    // THE SIX GENERATION 4 IS ABOUT, each measured against the real validator with the real node_modules
    // evening before being written down here. Every one of them EXITED 0 with VERDICT PASS
    // and with ajv named nowhere in the output, because both superseded rules dropped the entry before
    // any bucket, which is what UNPLACED records.
    { key: "node_modules/ajv", entry: { resolved: "https://registry.npmjs.org/ajv/-/ajv-8.20.0.tgz" }, want: "unreadable", offset: "UNPLACED", drop: "UNPLACED", why: "an install entry with its `version` deleted claims an install with nothing to compare it against, and the pin it stands for left through a guard clause upstream of all five buckets" },
    { key: "node_modules/ajv", entry: { version: 8.2 }, want: "unreadable", offset: "UNPLACED", drop: "UNPLACED", why: "a JSON number is not a version string, and dropping it silently is how a pin goes uncompared" },
    { key: "node_modules/ajv", entry: { version: null }, want: "unreadable", offset: "UNPLACED", drop: "UNPLACED", why: "a null version is not a version string" },
    { key: "node_modules/ajv", entry: null, want: "unreadable", offset: "UNPLACED", drop: "UNPLACED", why: "an entry that is not an object has no version to read and no link to check, and `entry?.version` reached undefined and skipped rather than refusing" },
    { key: "node_modules/ajv", entry: ["8.20.0"], want: "unreadable", offset: "UNPLACED", drop: "UNPLACED", why: "an array is not an entry either, and it is named separately because typeof gives `object` for it" },
    { key: "node_modules/ajv", entry: { resolved: "packages/ajv", link: true, version: "8.20.0" }, want: "unreadable", offset: "pinned", drop: "pinned", why: "npm writes a link record OR a version, never both, so reading this as a link would lift a real pin out of the comparison on the strength of one added attribute" },

    // THE LEGITIMATE LINK RECORD, which is the shape this refusal must NOT swallow. npm writes exactly
    // this for a workspace member: the member's own key carries the version and this one carries the
    // link. It is set aside and named on the pass line, not refused, because nothing is wrong with it.
    { key: "node_modules/@downpipe/vectors-tool", entry: { resolved: "packages/vectors-tool", link: true }, want: "linked", offset: "UNPLACED", drop: "UNPLACED", why: "npm's link record for a workspace member carries no version because nothing was fetched, so there is nothing to compare and nothing wrong: it is set aside and printed, never refused" },
    { key: "node_modules/left-pad", entry: { resolved: "packages/left-pad", link: false }, want: "unreadable", offset: "UNPLACED", drop: "UNPLACED", why: "`link` is tested for the boolean true rather than for truthiness, so an entry claiming not to be a link and carrying no version is a malformed install record rather than a link" },

    // THE FOUR GENERATION 5 IS ABOUT: the npm ALIAS record, where the lockfile itself says the directory
    // holds a package other than the one it is named for. VERIFIED by running npm rather than read off
    // documentation: `npm i ajv@npm:fast-deep-equal@3.1.3` writes a `name` inside the node_modules/ajv
    // entry, and installs a package.json declaring fast-deep-equal there. Every generation before this
    // one filed it as an ordinary pin, compared the version, found it equal to the version the alias
    // record itself supplied, and printed the DIRECTORY's name on the pass line as the package compared.
    { key: "node_modules/aliased-dir", entry: { name: "fast-deep-equal", version: "3.1.3", resolved: "https://registry.npmjs.org/fast-deep-equal/-/fast-deep-equal-3.1.3.tgz" }, want: "aliased", offset: "pinned", drop: "pinned", why: "npm's own alias record, written exactly as npm writes it: the entry declares another package's name, so the directory is not a pin of the name it carries" },
    { key: "node_modules/@scope/aliased", entry: { name: "@other/real", version: "1.0.0" }, want: "aliased", offset: "pinned", drop: "pinned", why: "an alias under a scoped directory name is still an alias, and both names survive classification whole because the refusal prints them" },
    { key: "node_modules/aliased-and-optional", entry: { name: "elsewhere", version: "1.0.0", optional: true }, want: "aliased", offset: "excluded", drop: "excluded", why: "placement before exclusion, one generation on: marking an alias optional must not lift it into the excluded list, where the pass line would print the directory's name and never say another package sits in it" },
    { key: "node_modules/honest", entry: { name: "honest", version: "1.0.0" }, want: "pinned", offset: "pinned", drop: "pinned", why: "a `name` EQUAL to the directory's own name is not an alias and must not be treated as one, or a redundant field would set aside a real pin" },
  ];

  // The floor is the count at the time this was written. Deleting a case rather than fixing what it
  // catches is the cheapest way to make a self-test green, so it is a failure here.
  const CASE_FLOOR = 30;
  // Every key on which the shipped rule and a superseded rule must differ, written out rather than
  // counted, because a floor can be met by the wrong cases. If a key leaves a list the fix it stands for
  // has gone with it. Keys repeat across cases here, so the entries are case INDEXES and the lists are
  // derived from the table itself rather than maintained beside it: a case that stops disagreeing is
  // caught by the per-case assertion below, and these two lists assert that the disagreement sets are
  // non-empty and that each superseded rule is distinguished by at least the cases it was written for.
  const MUST_DISAGREE_OFFSET = [
    "node_modules\\ajv",
    "packages/my-node_modules/lib",
    "node_modules/@node_modules/foo",
    "node_modules/ajv/node_modules/fast-deep-equal",
    "node_modules",
    "node_modules/node_modules",
    "node_modules/a/b/c",
    "node_modules/aliased-dir",
    "node_modules/@scope/aliased",
    "node_modules/aliased-and-optional",
  ];
  // The drop is the whole of generation 4, so these are the shapes that reached no bucket at all under
  // generation 3, plus the one it filed as a pin that it had no business filing.
  const MUST_DISAGREE_DROP = [
    "node_modules/ajv",
    "node_modules/@downpipe/vectors-tool",
    "node_modules/left-pad",
    "",
    "node_modules/aliased-dir",
    "node_modules/@scope/aliased",
    "node_modules/aliased-and-optional",
  ];

  let fails = 0;
  let checks = 0;
  const disagreedOffset = new Set();
  const disagreedDrop = new Set();

  const assert = (ok, desc) => {
    checks += 1;
    if (!ok) {
      fails += 1;
      console.error("validate --self-test FAIL: " + desc);
    }
  };

  for (const c of cases) {
    // One key at a time, so a case cannot be carried by another case's output.
    const one = { [c.key]: c.entry };
    const got = dispositionOf(classifyLockPackages(one), c.key);
    assert(got === c.want, JSON.stringify(c.key) + " " + JSON.stringify(c.entry) + ": wanted " + c.want + ", got " + got + " (" + c.why + ")");
    // UNPLACED and AMBIGUOUS are reports that the classifier did not place the key. Neither is a
    // disposition, so neither may be what a case wants of the SHIPPED rule.
    assert(c.want !== "UNPLACED" && !c.want.startsWith("AMBIGUOUS"), JSON.stringify(c.key) + ": a case may not want " + c.want + " of the shipped rule; that is a failure to place, not a placement");

    const old2 = dispositionOf(supersededByOffset(one), c.key);
    assert(old2 === c.offset, JSON.stringify(c.key) + " " + JSON.stringify(c.entry) + ": the offset rule was recorded as reaching " + c.offset + " but reaches " + old2);
    if (old2 !== c.want) disagreedOffset.add(c.key);

    const old3 = dispositionOf(supersededByDrop(one), c.key);
    assert(old3 === c.drop, JSON.stringify(c.key) + " " + JSON.stringify(c.entry) + ": the drop rule was recorded as reaching " + c.drop + " but reaches " + old3);
    if (old3 !== c.want) disagreedDrop.add(c.key);
  }

  // The version has to survive classification, not merely the name. A classifier that filed every key
  // correctly but carried no version would pass every assertion above and compare nothing downstream.
  const versionCarried = classifyLockPackages({ "node_modules/ajv": { version: "8.20.0" } }).pinned.get("ajv");
  assert(versionCarried === "8.20.0", "a pinned entry must carry its version through classification, got " + JSON.stringify(versionCarried));

  // A SOURCE-CONSISTENCY ASSERTION, AND IT IS LABELLED AS ONE. Both operands are module-level constants
  // of this file, so this comparison resolves nothing about any tree: it can only catch an edit to one
  // of the two lines that declare them, and it does, which was driven by retyping JUDGE and watching
  // this assertion take the self-test to exit 1 at 1 of 189. It is worth having for that and it is not
  // evidence about an install. The thing that reads the world is judgeModuleWithinGradedPackage, which
  // resolves both and requires the module to sit inside the package that was graded.
  //
  // A CENSUS found this to be the ONLY such assertion in the repository's.mjs gates, 1 of
  // 55 assertion conditions, and 11 of 2,598 in the Go tree, all eleven of those a frozen wire value
  // pinned against an independently written literal, which is double entry rather than a claim about a
  // tree. The rule the census applies: an assertion whose whole condition reads nothing but constants
  // declared in the same file.
  assert(
    AJV_MODULE === JUDGE || AJV_MODULE.startsWith(JUDGE + SEP),
    "JUDGE " + JSON.stringify(JUDGE) + " must be the package of AJV_MODULE " + JSON.stringify(AJV_MODULE) + ", or the floor pins a package this file does not load"
  );
  // whereJudgeWent must find the judge missing whenever it is not in the compared set, and must be
  // silent when it is. Driven both ways rather than only the one that fires.
  {
    const compared = classifyLockPackages({ [NM + JUDGE]: { version: "8.20.0" } });
    assert(whereJudgeWent(compared, { [NM + JUDGE]: { version: "8.20.0" } }) === null, "whereJudgeWent must be silent when the judge was compared");
    const stripped = { [NM + JUDGE]: { resolved: "x" }, [NM + "other"]: { version: "1.0.0" } };
    // The judge is unreadable here, so the classifier refuses upstream in the real run; the floor is
    // still asserted to notice, because the two arms are independent and either alone is a single point.
    const only = classifyLockPackages({ [NM + "other"]: { version: "1.0.0" } });
    assert(whereJudgeWent(only, { [NM + "other"]: { version: "1.0.0" } }) !== null, "whereJudgeWent must report a judge that was not compared");
    assert(
      (whereJudgeWent(only, stripped) ?? "").includes(NM + JUDGE),
      "whereJudgeWent must name the key the judge appears under when it reached no compared bucket, got " + JSON.stringify(whereJudgeWent(only, stripped))
    );
    const linkedJudge = classifyLockPackages({ [NM + JUDGE]: { resolved: "packages/ajv", link: true }, [NM + "other"]: { version: "1.0.0" } });
    assert(
      (whereJudgeWent(linkedJudge, {}) ?? "").includes("link record"),
      "a judge set aside as a link record must be reported as such rather than as absent, got " + JSON.stringify(whereJudgeWent(linkedJudge, {}))
    );
    // THE ALIAS ON THE JUDGE'S OWN KEY, in the exact shape npm wrote when this was driven: the run must
    // refuse and must say the lockfile pins the other package there, rather than reporting the judge as
    // simply absent, because "absent" would send a reader looking for a missing entry that is present.
    const aliasedJudge = classifyLockPackages({ [NM + JUDGE]: { name: "fast-deep-equal", version: "3.1.3", resolved: "https://registry.npmjs.org/fast-deep-equal/-/fast-deep-equal-3.1.3.tgz" } });
    const aliasWent = whereJudgeWent(aliasedJudge, {});
    assert(aliasWent !== null, "a judge whose lockfile entry is an npm alias record must not be reported as compared");
    assert(
      (aliasWent ?? "").includes("ALIAS") && (aliasWent ?? "").includes("fast-deep-equal"),
      "an aliased judge must be reported as an alias and must name the package the lockfile puts there, got " + JSON.stringify(aliasWent)
    );
    assert(aliasedJudge.pinned.size === 0, "an alias record must not reach the compared set, got " + [...aliasedJudge.pinned.keys()].join(", "));
  }

  // THE NUMBER OF TREES IS COUNTED, NOT WRITTEN DOWN. The summary at the bottom of this function used to
  // say "six installed trees" and had said it since the commit that introduced the sentence. Driven, the
  // count is EIGHT: six call sites, one of which is a three-iteration loop, and every one of the eight
  // probe answers differs from the other seven. Six is the number of CALL SITES, which is not what the
  // sentence claims to report and is not what a reader of it would go and check.
  //
  // NOTHING PINNED IT, which is why it drifted rather than being caught: the self-test can add a tree
  // and stay at exit 0 with the sentence still saying six. So the sentence now reads the recorder below,
  // the recorder counts what actually went through compareInstalled, and three assertions hold the
  // count, the distinctness and the "none of which exist on disk" half of the same clause.
  //
  // THE RECORDER CALLS THE PROBE ITSELF, one extra time per pin per tree. Every probe here is a pure
  // lookup over two frozen objects, so the extra call cannot perturb what the shipped rule then sees.
  const installedTrees = new Map();
  let installedTreeDrives = 0;
  const driveInstalled = (pins, probe) => {
    installedTreeDrives += 1;
    const answers = [...pins.keys()].map((name) => [name, probe(name)]);
    installedTrees.set(JSON.stringify(answers), answers);
    return compareInstalled(pins, probe);
  };

  // THE COMPARISON STAGE, DRIVEN OVER TREES THAT DO NOT EXIST ON DISK. compareInstalled takes its probe
  // as an argument for exactly this: the shipped function is driven, with no install, over the eight
  // trees that were hand-built and measured, and the rule it supersedes is driven beside
  // it over the same trees and REQUIRED to accept what this one rejects. A control that cannot fail
  // against the version it is meant to reject is a zero that merely looks checked.
  {
    // GENERATION 4, verbatim: the version was read and the name was not. This is the rule that let a
    // directory named for the judge, holding another package at the version the lockfile named, print
    // "was compared and resolves at the version package-lock.json names".
    const supersededByVersionOnly = (pins, probe) => {
      const verified = new Map();
      const absent = [];
      const wrong = [];
      const unreadable = [];
      for (const [name, want] of pins) {
        const got = probe(name);
        if (got.kind === "absent") {
          absent.push({ name, want });
          continue;
        }
        if (got.kind === "unreadable") {
          unreadable.push({ name, want, why: got.why });
          continue;
        }
        if (got.version !== want) {
          wrong.push({ name, want, got: got.version });
          continue;
        }
        verified.set(name, { name: got.name, version: got.version });
      }
      return { verified, absent, wrong, misnamed: [], unreadable, unidentifiable: [] };
    };

    const pins = new Map([
      [JUDGE, "8.20.0"],
      ["fast-uri", "3.1.5"],
    ]);
    // An honest tree, and then one override at a time on the judge. The other package is left honest in
    // every tree, so an assertion about the judge cannot be satisfied by the tree being uniformly broken.
    const honest = { [JUDGE]: { kind: "read", name: JUDGE, version: "8.20.0", at: "/n/ajv/package.json" } };
    const probeFor = (over) => (name) => {
      if (Object.prototype.hasOwnProperty.call(over, name)) return over[name];
      if (Object.prototype.hasOwnProperty.call(honest, name)) return honest[name];
      return { kind: "read", name, version: pins.get(name), at: "/n/" + name + "/package.json" };
    };
    const closes = (r, label) => {
      const n = r.verified.size + r.absent.length + r.wrong.length + r.misnamed.length + r.unreadable.length + r.unidentifiable.length;
      assert(n === pins.size, "compareInstalled must give every pinned name exactly one outcome on " + label + ": " + pins.size + " given, " + n + " accounted for");
    };

    const clean = driveInstalled(pins, probeFor({}));
    assert(clean.verified.get(JUDGE)?.name === JUDGE && clean.verified.get(JUDGE)?.version === "8.20.0", "an honest tree must verify the judge by name AND version");
    assert(clean.misnamed.length === 0 && clean.wrong.length === 0, "an honest tree must produce no finding");
    closes(clean, "an honest tree");

    // ATTACK 1 AND 2 REACH THE SAME PLACE HERE. An alias install is refused a stage earlier, in the
    // classifier, because the lockfile declared it; a package.json that simply lies about its name is
    // caught only here, and this is the tree that measured EXIT 0 PASS 112 before the name was read.
    const lying = probeFor({ [JUDGE]: { kind: "read", name: "corporate-schema-tool", version: "8.20.0", at: "/n/ajv/package.json" } });
    const caught = driveInstalled(pins, lying);
    assert(!caught.verified.has(JUDGE), "a directory holding a package that declares another name must not be verified");
    assert(
      caught.misnamed.length === 1 && caught.misnamed[0].declared === "corporate-schema-tool" && caught.misnamed[0].name === JUDGE,
      "a misnamed install must be reported as misnamed and must name both the pin and what it found, got " + JSON.stringify(caught.misnamed)
    );
    assert(caught.wrong.length === 0, "a misnamed install at the pinned version is not a WRONG VERSION finding, and reporting it as one would send the reader to `npm ci` for a tree npm ci built");
    closes(caught, "a misnamed tree");
    // THE CONTROL, AND IT MUST FAIL. The superseded rule has to accept this tree, or these assertions
    // are not testing the name fix.
    const old = supersededByVersionOnly(pins, lying);
    assert(
      old.verified.has(JUDGE),
      "the version-only rule must ACCEPT the misnamed tree, or the assertions above are not testing the name fix. It rejected it."
    );

    // A package.json with no usable name, and one with no usable version. Both are refusals rather than
    // findings, and neither may pass: an identity that cannot be read is not an identity that matched.
    for (const [label, over] of [
      ["no name", { kind: "read", name: undefined, version: "8.20.0", at: "/n/ajv/package.json" }],
      ["empty name", { kind: "read", name: "", version: "8.20.0", at: "/n/ajv/package.json" }],
      ["no version", { kind: "read", name: JUDGE, version: undefined, at: "/n/ajv/package.json" }],
    ]) {
      const r = driveInstalled(pins, probeFor({ [JUDGE]: over }));
      assert(!r.verified.has(JUDGE), "a judge whose package.json has " + label + " must not be verified");
      assert(r.unidentifiable.length === 1 && r.unidentifiable[0].name === JUDGE, "a judge whose package.json has " + label + " must be reported as unidentifiable, got " + JSON.stringify(r));
      closes(r, "a tree with " + label);
      const o = supersededByVersionOnly(pins, probeFor({ [JUDGE]: over }));
      if (label !== "no version") {
        assert(o.verified.has(JUDGE), "the version-only rule must ACCEPT the tree with " + label + ", or that assertion is not testing the identity fix");
      }
    }

    // And the outcomes that predate this generation still reach the same place, because a fix that
    // quietly changed them would be a regression nothing else here would catch.
    const missing = driveInstalled(pins, probeFor({ [JUDGE]: { kind: "absent" } }));
    assert(missing.absent.length === 1 && missing.absent[0].name === JUDGE, "an uninstalled judge must still be reported absent");
    closes(missing, "an absent tree");
    const stale = driveInstalled(pins, probeFor({ [JUDGE]: { kind: "read", name: JUDGE, version: "8.17.1", at: "/n/ajv/package.json" } }));
    assert(stale.wrong.length === 1 && stale.wrong[0].got === "8.17.1", "a stale judge must still be reported as the wrong version");
    closes(stale, "a stale tree");
    const shy = driveInstalled(pins, probeFor({ [JUDGE]: { kind: "unreadable", why: "exports map declines ./package.json" } }));
    assert(shy.unreadable.length === 1 && shy.unreadable[0].name === JUDGE, "a judge that will not expose its package.json must still be a refusal rather than a finding");
    closes(shy, "a tree that will not expose package.json");
  }

  // THE CONTAINMENT TEST, driven both ways and with the prefix trap it exists for. This is the only
  // thing tying the package that was graded to the module main() actually loads: without it two
  // independent resolutions ran and nothing said they landed in the same place.
  {
    const S = path.sep;
    assert(resolvesInside(`${S}n${S}ajv${S}package.json`, `${S}n${S}ajv${S}dist${S}2020.js`), "a module inside the graded package directory must be accepted");
    assert(!resolvesInside(`${S}n${S}ajv${S}package.json`, `${S}n${S}elsewhere${S}dist${S}2020.js`), "a module in another directory entirely must be rejected");
    // The prefix trap, which is the same mistake classifyKey's segment test exists to avoid one level up.
    assert(
      !resolvesInside(`${S}n${S}ajv${S}package.json`, `${S}n${S}ajv-extra${S}dist${S}2020.js`),
      "`ajv-extra` merely STARTS WITH `ajv` and is a different package, so a prefix test without the separator would accept it"
    );
    assert(resolvesInside(`${S}n${S}ajv${S}package.json`, `${S}n${S}ajv${S}index.js`), "a module at the top of the graded package directory is inside it, so a test requiring a subdirectory would false-red a single-file package");
    assert(!resolvesInside(`${S}n${S}ajv${S}package.json`, `${S}n${S}ajv`), "the package directory is not a file inside itself");
  }

  // ENTRY CONTAINMENT OVER ALL FIVE PINS, driven over trees that do not exist on disk. The resolver is
  // injected, so what runs here is the shipped rule rather than a restatement of it.
  {
    const S = path.sep;
    const dir = (n) => `${S}n${S}${n}`;
    const at = (n, f) => `${S}n${S}${n}${S}${f}`;
    const names = ["ajv", "fast-deep-equal", "fast-uri", "json-schema-traverse", "require-from-string"];
    const honest = (n) => ({ kind: "resolved", pkgJson: at(n, "package.json"), entry: at(n, "index.js") });
    const closes = (r, label) => {
      const filed = r.contained.length + r.outside.length + r.noEntry.length + r.unresolvable.length;
      assert(filed === names.length, "entryContainment must give every name exactly one outcome on " + label + ": " + names.length + " given, " + filed + " accounted for");
    };

    const clean = entryContainment(names, honest);
    assert(clean.contained.length === 5 && clean.outside.length === 0, "an honest tree must contain all five entries, got " + JSON.stringify(clean));
    closes(clean, "an honest tree");

    // THE ESCAPE THIS RULE EXISTS FOR, in the exact shape it was measured in: `main` edited
    // to climb out of the tree, so the entry resolves into the repository's own scripts/ directory while
    // the package.json the comparison reads is untouched. It must FAIL, and it must name the package.
    const escaped = entryContainment(names, (n) => (n === "fast-uri" ? { kind: "resolved", pkgJson: at("fast-uri", "package.json"), entry: `${S}repo${S}scripts${S}marker.js` } : honest(n)));
    assert(escaped.outside.length === 1 && escaped.outside[0].name === "fast-uri", "an entry resolving outside its own package directory must be reported as outside, got " + JSON.stringify(escaped));
    assert(escaped.outside[0].dir === dir("fast-uri"), "the finding must name the graded package directory it escaped");
    closes(escaped, "an escaped tree");

    // THE PREFIX TRAP AGAIN, one level up: a sibling directory whose name merely starts with the
    // package's name is a different package, and a containment test without the separator accepts it.
    const sibling = entryContainment(names, (n) => (n === "ajv" ? { kind: "resolved", pkgJson: at("ajv", "package.json"), entry: at("ajv-extra", "index.js") } : honest(n)));
    assert(sibling.outside.length === 1 && sibling.outside[0].name === "ajv", "`ajv-extra/index.js` is not inside `ajv`, so it must be reported outside");

    // AND THE TWO NON-FINDINGS, which are filed and printed rather than dropped. A package exposing no
    // bare entry has no entry to escape through; one whose entry will not resolve is a refusal, because
    // nothing is known about where its code lives.
    const shy = entryContainment(names, (n) => (n === "require-from-string" ? { kind: "no-entry", why: "exports declines \".\"" } : honest(n)));
    assert(shy.noEntry.length === 1 && shy.outside.length === 0, "a package exposing no bare entry must be filed as no-entry, not as a finding");
    closes(shy, "a tree with a package exposing no bare entry");
    const broken = entryContainment(names, (n) => (n === "fast-deep-equal" ? { kind: "unresolvable", why: "main points at a file that is not there" } : honest(n)));
    assert(broken.unresolvable.length === 1 && broken.outside.length === 0, "an entry that will not resolve must be a refusal rather than a finding");
    closes(broken, "a tree with an unresolvable entry");
  }

  // THE LOAD CENSUS, which is the only rule in this file that reads what RAN rather than what the
  // metadata says. Driven over module lists that never existed, so the shipped decision is what runs.
  {
    const S = path.sep;
    const dirs = [`${S}n${S}ajv`, `${S}n${S}fast-uri`];
    const inAjv = `${S}n${S}ajv${S}dist${S}2020.js`;

    const ok = loadedModuleVerdict([inAjv, `${S}n${S}ajv${S}dist${S}core.js`, `${S}n${S}fast-uri${S}index.js`], dirs, inAjv, []);
    assert(ok.kind === "ok" && ok.total === 3 && ok.inside.size === 2, "a process that loaded only pinned code must pass, got " + JSON.stringify(ok.kind));

    // THE ESCAPE THIS RULE EXISTS FOR, measured with `main` left alone and ONE `require`
    // climbing out of the tree: every metadata check above is satisfied and foreign code still ran.
    const foreign = loadedModuleVerdict([inAjv, `${S}repo${S}scripts${S}marker.js`], dirs, inAjv, []);
    assert(foreign.kind === "fail", "a process that loaded a module from outside every pinned directory must FAIL, got " + foreign.kind);
    assert(foreign.foreign.length === 1 && foreign.foreign[0] === `${S}repo${S}scripts${S}marker.js`, "the finding must name the foreign module");

    // THE PREFIX TRAP, third and last place it appears: `/n/ajv-extra/x.js` starts with `/n/ajv`.
    const prefix = loadedModuleVerdict([inAjv, `${S}n${S}ajv-extra${S}x.js`], dirs, inAjv, []);
    assert(prefix.kind === "fail" && prefix.foreign[0] === `${S}n${S}ajv-extra${S}x.js`, "`ajv-extra` is a different package, so a prefix test without the separator would have called this contained");

    // THE WALK THAT NEVER VISITS, which is the reason the instrument carries its own positive control. An
    // empty cache files nothing, finds nothing foreign and would otherwise be indistinguishable from a
    // clean run. It must REFUSE, not pass.
    const empty = loadedModuleVerdict([], dirs, inAjv, []);
    assert(empty.kind === "refuse", "a census that visited nothing must refuse rather than report a clean run, got " + empty.kind);
    const wrongWalk = loadedModuleVerdict([`${S}n${S}fast-uri${S}index.js`], dirs, inAjv, []);
    assert(wrongWalk.kind === "refuse", "a census that did not visit the module the process loaded must refuse, got " + wrongWalk.kind);

    // AND THE CONTROL THAT MAKES THE ONE ABOVE MEAN SOMETHING: the same corpus with the visited module
    // present must NOT refuse, or `refuse` is being returned for some other reason and the never-visited
    // assertion is passing by accident.
    const visited = loadedModuleVerdict([`${S}n${S}fast-uri${S}index.js`, inAjv], dirs, inAjv, []);
    assert(visited.kind === "ok", "the same corpus WITH the loaded module present must pass, or the never-visited assertion is not testing what it claims");

    // AND THE POPULATION THAT RULE IS ASKED ABOUT, driven over records that never happened. Both bypasses
    // reproduced are shapes of ONE defect: the require cache answers for what is still in
    // it, and the census used to ask nothing else. Each is a case here.
    const url = (p) => "file://" + p.split(path.sep).join("/");
    const toPath = (u) => u.slice("file://".length).split("/").join(path.sep);
    const marker = `${S}repo${S}scripts${S}marker.js`;

    const straight = censusPopulation([url(inAjv), url(`${S}n${S}fast-uri${S}index.js`)], [inAjv, `${S}n${S}fast-uri${S}index.js`], toPath);
    assert(straight.kind === "ok" && straight.keys.length === 2, "a record and a cache that agree must give the population they agree on, got " + JSON.stringify(straight.kind) + " over " + (straight.keys?.length ?? 0));
    assert(straight.outsideCache.length === 0 && straight.builtins.length === 0, "nothing was deleted and nothing was a builtin, so both of those must be empty");

    // BYPASS ONE. The module ran, the recorder filed it, and then it removed its own cache entry. The
    // cache alone reports the clean run; the union reports what happened.
    const deleted = censusPopulation([url(inAjv), url(marker)], [inAjv], toPath);
    assert(deleted.kind === "ok" && deleted.keys.includes(marker), "a module that deleted its own cache entry must still be in the population, and the population was " + JSON.stringify(deleted.keys ?? deleted.why));
    assert(deleted.outsideCache.length === 1 && deleted.outsideCache[0] === marker, "the module the cache no longer holds must be reported as such");
    assert(loadedModuleVerdict(deleted.keys, dirs, inAjv, []).kind === "fail", "bypass one must reach a FAIL through the rule, not merely be present in the population");
    // AND THE CONTROL FOR IT: the same population without the union, which is what the cache alone gives,
    // must PASS. Without this the assertion above could hold for a rule that fails on anything.
    assert(loadedModuleVerdict([inAjv], dirs, inAjv, []).kind === "ok", "the cache alone must PASS on bypass one, or the union is not what is closing it");

    // BYPASS TWO. An ES module cannot be in the require cache at all, so it is in the record and nowhere
    // else, and the same union carries it.
    const esm = censusPopulation([url(inAjv), url(`${S}repo${S}scripts${S}foreign.mjs`)], [inAjv], toPath);
    assert(esm.kind === "ok" && esm.keys.includes(`${S}repo${S}scripts${S}foreign.mjs`), "an ES module the cache will never hold must still be in the population");
    assert(loadedModuleVerdict(esm.keys, dirs, inAjv, []).kind === "fail", "bypass two must reach a FAIL through the rule");

    // THE RECORDER'S OWN POSITIVE CONTROL. A cache holding what the recorder never saw means the recorder
    // was armed too late or is not recording what runs, and a recorder that filed NOTHING is the sharpest
    // case of it: the census would otherwise fall back to the cache and report the clean run that the two
    // bypasses already bought once.
    const late = censusPopulation([url(inAjv)], [inAjv, `${S}n${S}fast-uri${S}index.js`], toPath);
    assert(late.kind === "refuse", "a cache holding a module the recorder never saw must REFUSE, got " + late.kind);
    const recordedNothing = censusPopulation([], [inAjv], toPath);
    assert(recordedNothing.kind === "refuse", "a recorder that filed nothing while the cache holds a module must REFUSE rather than pass on the cache alone, got " + recordedNothing.kind);

    // THE VACUITY CONTROL. Two inputs that resolve and hold nothing between them is a census with nothing
    // to census, and reporting containment over it is the defect the whole check exists for.
    const nothing = censusPopulation([], [], toPath);
    assert(nothing.kind === "refuse", "a population built from an empty record and an empty cache must REFUSE, got " + nothing.kind);

    // A BUILTIN IS SET ASIDE AND COUNTED, not dropped, and a URL that is not a file URL reaches the
    // comparison as itself. `import("data:text/javascript,...")` runs source under no path whatever and
    // was driven through this hook, so it must not be filtered out on the way.
    const mixed = censusPopulation([url(inAjv), "node:fs", "data:text/javascript,0"], [inAjv], toPath);
    assert(mixed.kind === "ok" && mixed.builtins.length === 1 && mixed.builtins[0] === "node:fs", "a node builtin must be set aside and counted, got " + JSON.stringify(mixed.builtins ?? mixed.why));
    assert(mixed.keys.includes("data:text/javascript,0"), "a data: URL must reach the comparison as itself rather than being filtered out");
    assert(loadedModuleVerdict(mixed.keys, dirs, inAjv, []).kind === "fail", "source loaded from a data: URL is not inside any graded directory, so it must FAIL");

    // BYPASS THREE, AND IT IS A DIFFERENT SHAPE FROM THE OTHER TWO. Both of those are visible to a
    // comparison between the record and the cache. A module loaded BEFORE the recorder was armed is in
    // neither: a pre-arming CommonJS load is at least in the cache, so censusPopulation refuses on it,
    // but a pre-arming ES load is in nothing at all. MEASURED against the real arming
    // order, exit code read off the process: `import "../foreign-preload.mjs";` in ../lib/verdict-guard.mjs,
    // which this file statically imports, was EXIT 0 at VERDICT PASS 112 with the census printing the same
    // 88 a clean tree printed and the foreign file's marker written.
    //
    // SO THE CHECK IS ON WHERE THE RECORD STARTS, and the entry point is the one module whose presence
    // proves arming preceded it.
    const entryPath = `${S}repo${S}scripts${S}schema-validate${S}validate.mjs`;
    assert(entryObservedVerdict([inAjv, entryPath], entryPath).kind === "ok", "a record containing the entry point began before it, so it must be accepted");
    const unseenEntry = entryObservedVerdict([inAjv], entryPath);
    assert(unseenEntry.kind === "refuse", "a record that does not contain the entry point began after it, so it must REFUSE, got " + unseenEntry.kind);
    assert(unseenEntry.why.includes(entryPath), "the refusal must name the file it could not find in the record");
    // AND ITS VACUITY CONTROL: an empty record must refuse for the same reason rather than pass for want
    // of anything to disagree with.
    assert(entryObservedVerdict([], entryPath).kind === "refuse", "an empty record cannot contain the entry point, so it must REFUSE rather than pass on nothing");

    // THE PERMITTED LIST, which is what arming that early costs: this file, its preload and the shared
    // guard become visible to the census and none of them is inside a package the lockfile pins.
    const own = `${S}repo${S}scripts${S}lib${S}verdict-guard.mjs`;
    const permitted = loadedModuleVerdict([inAjv, own], dirs, inAjv, [own]);
    assert(permitted.kind === "ok" && permitted.own.length === 1 && permitted.own[0] === own, "a file the gate names as its own must be filed as its own and counted, got " + JSON.stringify(permitted.own ?? permitted.why));
    assert(permitted.total === 2, "the permitted file is counted in the total rather than subtracted from it, got " + permitted.total);
    // AND THE CONTROL THAT MAKES THAT MEAN SOMETHING: the same key, not named, must FAIL. Without it the
    // assertion above holds for a rule that passes on anything outside the graded directories.
    assert(loadedModuleVerdict([inAjv, own], dirs, inAjv, []).kind === "fail", "the same file NOT on the permitted list must FAIL, or the list is not what is permitting it");

    // THE LIST IS EXACT PATHS AND NOT A DIRECTORY, which is the whole reason it is a list. A sibling in
    // the same directory as a permitted file must still be foreign, or the two bypasses closed on
    // , whose shape is a file under scripts/ executed from inside node_modules, come back.
    const sibling = `${S}repo${S}scripts${S}lib${S}foreign-probe.cjs`;
    const notPermitted = loadedModuleVerdict([inAjv, sibling], dirs, inAjv, [own]);
    assert(notPermitted.kind === "fail" && notPermitted.foreign[0] === sibling, "a sibling of a permitted file is not permitted, and naming a directory instead of files would have passed it");
    // THE PREFIX TRAP ONCE MORE, at the permitted list this time: `verdict-guard.mjs.bak` starts with the
    // permitted path, and an `includes`-free prefix test would accept it.
    const prefixed = loadedModuleVerdict([inAjv, own + ".bak"], dirs, inAjv, [own]);
    assert(prefixed.kind === "fail" && prefixed.foreign[0] === own + ".bak", "a path merely beginning with a permitted path is a different file and must FAIL");

    // AND THE ARITHMETIC STILL CLOSES against the input with the new bucket in it, which is the check that
    // stops a key leaving through a bucket nobody counts.
    const closed = loadedModuleVerdict([inAjv, own, `${S}repo${S}scripts${S}marker.js`], dirs, inAjv, [own]);
    assert(closed.kind === "fail" && closed.own.length === 1 && closed.foreign.length === 1 && closed.total === 3, "every key must be filed into exactly one of permitted, inside and foreign, got " + JSON.stringify({ own: closed.own?.length, foreign: closed.foreign?.length, total: closed.total }));
  }

  // THE LAUNCHER IS PART OF THE CLAIM, so it is read rather than assumed. The recorder is armed by
  // `--import`, which lives on the command line and not in this file, and a run that lost the flag
  // refuses at exit 2 rather than reporting a partial census. That refusal is the backstop; this
  // assertion is the thing that notices at self-test time, before a real run has to.
  //
  // IT READS THE REAL package.json IN THIS DIRECTORY, not a fixture, because a fixture would agree with
  // whatever it was written to say. The preload's own path is checked against the same file the census
  // permits, so the two cannot drift apart.
  {
    const pkgPath = path.join(SELF_DIR, "package.json");
    let pkg;
    try {
      pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
    } catch (err) {
      pkg = null;
      assert(false, "this directory's own package.json must be readable, because the invocation it carries is what arms the load recorder: " + err.message);
    }
    const validateScript = pkg?.scripts?.validate;
    assert(typeof validateScript === "string" && validateScript.length > 0, "package.json must carry a `validate` script, and it carries " + JSON.stringify(validateScript));
    assert(
      typeof validateScript === "string" && validateScript.includes("--import ./arm-load-recorder.mjs"),
      "the `validate` script must arm the load recorder through `--import ./arm-load-recorder.mjs`, or every run of it censuses a population that begins after this file's own static imports. It is " + JSON.stringify(validateScript)
    );
    // AND THE PRELOAD IT NAMES MUST BE THERE, so the flag cannot point at nothing. A `--import` of a
    // missing file is a startup error rather than a silent pass, but a self-test that never looks would
    // report green on a tree where the flag has been pointed elsewhere.
    assert(fs.existsSync(path.join(SELF_DIR, "arm-load-recorder.mjs")), "the preload the `validate` script names must exist at " + path.join(SELF_DIR, "arm-load-recorder.mjs"));
    // THE POSITIVE CONTROL FOR THE TWO ABOVE: the same test applied to a script string that does not arm
    // the recorder has to fail, or it is not testing the flag.
    assert(!"node validate.mjs".includes("--import ./arm-load-recorder.mjs"), "the flag test must reject an invocation without the flag, or it is satisfied by any string");
  }

  // SOUNDNESS AND TOTALITY OVER THE WHOLE CORPUS. Keys repeat in the table, so the corpus is built from
  // the DISTINCT keys, each carrying the last entry written for it, and the identity is taken against
  // that map rather than against the case count.
  const all = {};
  for (const c of cases) all[c.key] = c.entry;
  const whole = classifyLockPackages(all);
  const violations = bucketViolations(whole, all);
  assert(violations.length === 0, "the shipped rule filed " + violations.length + " key(s) into a bucket whose defining property they do not have, or filed fewer keys than it was given:\n    " + violations.join("\n    "));

  // AND THE POSITIVE CONTROLS FOR THOSE ASSERTIONS, one per generation, of the shape they are meant to
  // catch rather than a convenient one: the same property test, over the same corpus, pointed at each
  // superseded rule. It has to FAIL on both. If it passes on either, it is not testing that fix.
  const offsetViolations = bucketViolations(supersededByOffset(all), all);
  assert(
    offsetViolations.length > 0,
    "the bucket-property assertions pass on the OFFSET rule as well, so they are not testing the segment fix. They must fail on it."
  );
  const dropViolations = bucketViolations(supersededByDrop(all), all);
  assert(
    dropViolations.length > 0,
    "the bucket-property assertions pass on the DROP rule as well, so they are not testing the drop fix. They must fail on it."
  );
  // NAMED RATHER THAN COUNTED, because a violation of any kind would satisfy the two assertions above
  // and only one kind is the drop. The drop rule must fail the TOTALITY identity specifically, and it
  // must fail it by having filed FEWER keys than it was given.
  assert(
    dropViolations.some((v) => /reached no bucket at all/.test(v)),
    "the DROP rule must fail the totality identity by filing fewer keys than it was given, and it did not. Its violations were:\n    " + dropViolations.join("\n    ")
  );
  // And the shipped rule must file every key of that same corpus, which is the other direction of the
  // same identity and is what the assertion above would still pass if the corpus held no dropped shape.
  {
    const byKey = new Set([...whole.roots, ...whole.workspaces, ...whole.nested, ...whole.unmodelled.map((u) => u.key), ...whole.unreadable.map((u) => u.key), ...whole.aliased.map((a) => a.key)]);
    const filed = byKey.size + whole.pinned.size + whole.excluded.length + whole.linked.length;
    assert(
      filed === Object.keys(all).length,
      "the shipped rule must file every key it is given: " + Object.keys(all).length + " given, " + filed + " filed"
    );
  }

  // The whole-corpus dispositions that the printed lines depend on, named rather than counted.
  assert(
    whole.workspaces.length === 2 && whole.workspaces.includes("packages/vectors-tool") && whole.workspaces.includes("packages/my-node_modules/lib"),
    "the whole-corpus run must set aside exactly the two workspace members, got: " + whole.workspaces.join(", ")
  );
  assert(
    whole.linked.length === 1 && whole.linked[0] === "@downpipe/vectors-tool",
    "the whole-corpus run must set aside exactly the one legitimate npm link record, got: " + whole.linked.join(", ")
  );
  assert(
    whole.unmodelled.length === 4,
    "the whole-corpus run must refuse exactly the four unmodelled keys, got " + whole.unmodelled.length + ": " + whole.unmodelled.map((u) => u.key).join(", ")
  );
  assert(
    whole.unmodelled.every((u) => typeof u.why === "string" && u.why.length > 0),
    "every unmodelled key must carry the reason it could not be placed, because the refusal prints it"
  );
  assert(
    whole.unreadable.every((u) => typeof u.why === "string" && u.why.length > 0),
    "every unreadable entry must carry the reason it could not be read, because the refusal prints it"
  );
  assert(whole.roots.length === 1 && whole.roots[0] === "", "the root key must be filed as root rather than dropped, got: " + JSON.stringify(whole.roots));
  assert(
    whole.aliased.length === 3 && whole.aliased.every((a) => typeof a.declared === "string" && a.declared !== a.name),
    "the whole-corpus run must set aside exactly the three npm alias records, each naming the package the lockfile puts at that directory, got " +
      whole.aliased.map((a) => a.key + " -> " + a.declared).join(", ")
  );

  // The control on the corpus itself. If the shipped rule and a superseded rule ever stop disagreeing on
  // one of these keys, this file is no longer testing the fix that key stands for.
  for (const key of MUST_DISAGREE_OFFSET) {
    assert(
      disagreedOffset.has(key),
      "the shipped rule and the OFFSET rule now AGREE on " + JSON.stringify(key) + ". Either the fix was reverted or the case was softened."
    );
  }
  for (const key of MUST_DISAGREE_DROP) {
    assert(
      disagreedDrop.has(key),
      "the shipped rule and the DROP rule now AGREE on " + JSON.stringify(key) + ". Either the fix was reverted or the case was softened."
    );
  }
  assert(cases.length >= CASE_FLOOR, "the self-test has " + cases.length + " case(s), below its floor of " + CASE_FLOOR + "; it is no longer proving the classes.");

  // THE EMPTY-VECTOR POLICY, DRIVEN OFFLINE over corpora that do not exist on disk, for the same reason
  // the lockfile classifier is: the shapes that matter most are the ones the real corpus does not hold.
  // A run directory holding no root manifest occurs zero times in 56 today, so without a fixture that
  // arm would ship untested and be discovered by the vector that trips it.
  //
  // fixtureTree builds the injected tree from a set of POSIX paths, files and directories kept apart, so
  // "absent" and "present but the wrong kind" are distinct inputs rather than one.
  //
  // A THIRD KIND, `others`, because the survey already reports one. An entry that is there and is
  // neither a file nor a directory is a real answer readdir can give, it is the OTHER value the
  // NOT_A_VECTOR cause can take, and without it that table's third direction has no fixture and would
  // ship on the strength of the code reading correctly.
  function fixtureTree(spec) {
    const dirs = new Set(spec.dirs.map((d) => path.join(VECTORS_DIR, d)));
    const files = new Set(spec.files.map((f) => path.join(VECTORS_DIR, f)));
    const others = new Set((spec.others ?? []).map((o) => path.join(VECTORS_DIR, o)));
    dirs.add(VECTORS_DIR);
    return {
      listDir(dir) {
        if (!dirs.has(dir)) return null;
        const kids = new Set();
        for (const p of [...dirs, ...files, ...others]) {
          if (p === dir) continue;
          if (path.dirname(p) === dir) kids.add(path.basename(p));
        }
        return [...kids];
      },
      isDirectory: (p) => dirs.has(p),
      isFile: (p) => files.has(p),
    };
  }

  // GENERATION 1 OF THE LISTERS, verbatim in behaviour: keep what you find, say nothing about the rest.
  // It is here so the totality assertion below can be required to FAIL against the rule it replaces,
  // rather than being a zero that merely looks checked.
  function supersededByListing(tree) {
    const manifests = [];
    const runlogs = [];
    for (const vector of tree.listDir(VECTORS_DIR) ?? []) {
      const runDir = path.join(VECTORS_DIR, vector, "archive", "run");
      if (!tree.isDirectory(runDir)) continue;
      for (const runId of tree.listDir(runDir) ?? []) {
        const file = path.join(runDir, runId, "root.manifest.json");
        if (tree.isFile(file)) manifests.push({ vector, file });
      }
    }
    for (const vector of tree.listDir(VECTORS_DIR) ?? []) {
      const file = path.join(VECTORS_DIR, vector, "archive", "_RECOVERY", "RUNLOG");
      if (tree.isFile(file)) runlogs.push({ vector, file });
    }
    return { manifests, runlogs };
  }

  // A corpus of two vectors that are complete, so each case below differs from the base in one thing.
  const baseDirs = [];
  const baseFiles = [];
  for (const v of ["alpha", "beta"]) {
    baseDirs.push(v, v + "/archive", v + "/archive/run", v + "/archive/run/R1", v + "/archive/_RECOVERY");
    baseFiles.push(v + "/archive/run/R1/root.manifest.json", v + "/archive/_RECOVERY/RUNLOG");
  }
  // Every fixture declaration carries the CAUSE the survey must report for that site, exactly as the
  // real tables do, so the third direction is driven by the shipped rule over fabricated corpora rather
  // than only over the corpus on disk.
  const decl = (cause) => ({ cause, why: "declared for the fixture, and its reason has to be at least forty characters long" });
  const emptyTables = { noRootManifest: {}, noRunlog: {}, runWithoutRootManifest: {}, notAVector: {} };
  const withTables = (over) => ({ ...emptyTables, ...over });

  const corpusCases = [
    {
      name: "a complete corpus with nothing declared",
      spec: { dirs: baseDirs, files: baseFiles },
      tables: emptyTables,
      refusals: 0,
      findings: 0,
      why: "both vectors yield both objects, so no declaration is needed and none is stale",
    },
    {
      name: "a vector with no archive/run and no declaration",
      spec: { dirs: baseDirs.filter((d) => !d.startsWith("beta/archive/run")), files: baseFiles.filter((f) => !f.startsWith("beta/archive/run")) },
      tables: emptyTables,
      refusals: 1,
      findings: 0,
      names: "beta",
      why: "the exact shape the four known-answer vectors have, undeclared",
    },
    {
      name: "the same vector, declared",
      spec: { dirs: baseDirs.filter((d) => !d.startsWith("beta/archive/run")), files: baseFiles.filter((f) => !f.startsWith("beta/archive/run")) },
      tables: withTables({ noRootManifest: { beta: decl("absent: there is no archive/run") } }),
      refusals: 0,
      findings: 0,
      why: "a declaration turns the refusal off and nothing else",
    },
    {
      name: "archive/run present as a FILE rather than a directory",
      spec: { dirs: baseDirs.filter((d) => !d.startsWith("beta/archive/run")), files: [...baseFiles.filter((f) => !f.startsWith("beta/archive/run")), "beta/archive/run"] },
      tables: emptyTables,
      refusals: 1,
      findings: 0,
      names: "beta",
      why: "present but the wrong kind of thing is not the same input as absent, and both refuse",
    },
    {
      name: "a run directory holding no root manifest",
      spec: { dirs: [...baseDirs, "beta/archive/run/R2"], files: baseFiles },
      tables: emptyTables,
      refusals: 1,
      findings: 0,
      names: "beta/R2",
      why: "the site with zero live instances in the real corpus; beta still yields R1, so a per-vector rule would miss it",
    },
    {
      name: "a vector with no RUNLOG and no declaration",
      spec: { dirs: baseDirs, files: baseFiles.filter((f) => f !== "beta/archive/_RECOVERY/RUNLOG") },
      tables: emptyTables,
      refusals: 1,
      findings: 0,
      names: "beta",
      why: "absent-runlog's shape: the manifest is still validated, so only the RUNLOG axis refuses",
    },
    {
      name: "a vector with no RUNLOG, declared",
      spec: { dirs: baseDirs, files: baseFiles.filter((f) => f !== "beta/archive/_RECOVERY/RUNLOG") },
      tables: withTables({ noRunlog: { beta: decl("absent: there is no archive/_RECOVERY/RUNLOG, and _RECOVERY is there and holds no RUNLOG.sig") } }),
      refusals: 0,
      findings: 0,
      why: "declaring the RUNLOG silence does not declare the manifest silence, and beta still yields a manifest",
    },
    {
      name: "a manifest declaration that the corpus does not bear out",
      spec: { dirs: baseDirs, files: baseFiles },
      tables: withTables({ noRootManifest: { beta: decl("absent: there is no archive/run") } }),
      refusals: 0,
      findings: 1,
      why: "the stale direction: nothing went ungraded, so it is a finding rather than a refusal",
    },
    {
      name: "a declaration naming a vector that is not there",
      spec: { dirs: baseDirs, files: baseFiles },
      tables: withTables({ noRunlog: { gamma: decl("absent: there is no archive/_RECOVERY/RUNLOG, and there is no archive/_RECOVERY at all") } }),
      refusals: 0,
      findings: 1,
      why: "a dangling declaration is the same class as a stale one and is caught by the same sweep",
    },
    {
      name: "an undeclared non-directory entry beside the vectors",
      spec: { dirs: baseDirs, files: [...baseFiles, "NOTES.txt"] },
      tables: emptyTables,
      refusals: 1,
      findings: 0,
      names: "NOTES.txt",
      why: "it is not a vector, so it must be named rather than filtered out by a rule wide enough to admit it",
    },
    {
      name: "the same entry, declared",
      spec: { dirs: baseDirs, files: [...baseFiles, "NOTES.txt"] },
      tables: withTables({ notAVector: { "NOTES.txt": decl("a file") } }),
      refusals: 0,
      findings: 0,
      why: "README.md's own case in the real corpus",
    },
    {
      name: "a vector that is empty on BOTH axes and declared on ONE",
      spec: { dirs: ["alpha", "alpha/archive", "alpha/archive/run", "alpha/archive/run/R1", "alpha/archive/_RECOVERY", "beta"], files: ["alpha/archive/run/R1/root.manifest.json", "alpha/archive/_RECOVERY/RUNLOG"] },
      tables: withTables({ noRootManifest: { beta: decl("absent: there is no archive/run") } }),
      refusals: 1,
      findings: 0,
      names: "beta",
      why: "one declaration must not cover the other axis, which is why there are two tables",
    },

    // THE THIRD DIRECTION. Every case above moves the SILENCE: it appears where nothing declared it, or
    // it goes away under a declaration that stayed. These four leave the silence exactly where the
    // declaration expects it and move the CAUSE underneath, which is the direction that used to pass.
    {
      name: "a declared empty manifest whose cause changed underneath it",
      spec: { dirs: [...baseDirs.filter((d) => !d.startsWith("beta/archive/run")), "beta/archive/run"], files: baseFiles.filter((f) => !f.startsWith("beta/archive/run")) },
      tables: withTables({ noRootManifest: { beta: decl("absent: there is no archive/run") } }),
      refusals: 0,
      findings: 1,
      findingNames: "beta",
      why: "beta still yields no root manifest, so the declaration is still satisfied and every other direction is silent; the reason it gives, no archive/run at all, has stopped being true because the directory is now there and empty",
    },
    {
      name: "a declared empty RUNLOG whose cause changed underneath it",
      spec: { dirs: baseDirs, files: [...baseFiles.filter((f) => f !== "beta/archive/_RECOVERY/RUNLOG"), "beta/archive/_RECOVERY/RUNLOG.sig"] },
      tables: withTables({ noRunlog: { beta: decl("absent: there is no archive/_RECOVERY/RUNLOG, and _RECOVERY is there and holds no RUNLOG.sig") } }),
      refusals: 0,
      findings: 1,
      findingNames: "beta",
      why: "absent-runlog's own discriminator, driven: the log is absent either way, and a signature appearing beside the hole is the difference between the negative vector and a broken one",
    },
    {
      name: "a declared non-vector entry whose cause changed underneath it",
      spec: { dirs: baseDirs, files: baseFiles, others: ["NOTES.txt"] },
      tables: withTables({ notAVector: { "NOTES.txt": decl("a file") } }),
      refusals: 0,
      findings: 1,
      findingNames: "NOTES.txt",
      why: "still not a directory, so the exemption still applies and every other direction is silent; it was granted to a file and the entry is no longer one",
    },
    {
      name: "a declaration that names no cause at all",
      spec: { dirs: baseDirs.filter((d) => !d.startsWith("beta/archive/run")), files: baseFiles.filter((f) => !f.startsWith("beta/archive/run")) },
      tables: withTables({ noRootManifest: { beta: { why: "a declaration carrying a reason and no cause whatsoever, which is the shape this refuses" } } }),
      refusals: 1,
      findings: 0,
      names: "beta",
      why: "an exemption that names no cause cannot be held to one, so it is could-not-check rather than a silence this run may permit",
    },
  ];

  const CORPUS_CASE_FLOOR = 16;
  assert(corpusCases.length >= CORPUS_CASE_FLOOR, "the corpus self-test has " + corpusCases.length + " case(s), below its floor of " + CORPUS_CASE_FLOOR);

  let supersededTotalityFailures = 0;
  for (const c of corpusCases) {
    const tree = fixtureTree(c.spec);
    const survey = surveyVectors(tree);
    assert(survey !== null, c.name + ": the fixture vectors directory must be listable");
    if (survey === null) continue;

    // TOTALITY, with the denominator read off the input. The fixture says how many entries the directory
    // holds, and every one must come back filed.
    assert(
      survey.vectors.length + survey.notDirectories.length === survey.entries,
      c.name + ": the survey filed " + (survey.vectors.length + survey.notDirectories.length) + " of " + survey.entries + " entry/entries"
    );

    const audit = auditVectorCoverage(survey, c.tables);
    assert(audit.refusals.length === c.refusals, c.name + ": wanted " + c.refusals + " refusal(s), got " + audit.refusals.length + " (" + audit.refusals.join(" | ") + ") [" + c.why + "]");
    assert(audit.findings.length === c.findings, c.name + ": wanted " + c.findings + " finding(s), got " + audit.findings.length + " (" + audit.findings.join(" | ") + ") [" + c.why + "]");
    if (c.names !== undefined) {
      assert(
        audit.refusals.some((r) => r.includes(JSON.stringify(c.names))),
        c.name + ": the refusal must NAME " + JSON.stringify(c.names) + ", and it said " + JSON.stringify(audit.refusals.join(" | "))
      );
    }
    // A COUNT IS NOT A NAME, and the third-direction cases are the ones where that matters most: a
    // finding raised for any other reason would satisfy the count and send the reader nowhere. So the
    // finding is required to name the site AND to print both causes, the one declared and the one
    // observed, since those two strings are the whole of the remedy.
    if (c.findingNames !== undefined) {
      assert(
        audit.findings.some((f) => f.includes(JSON.stringify(c.findingNames))),
        c.name + ": the finding must NAME " + JSON.stringify(c.findingNames) + ", and it said " + JSON.stringify(audit.findings.join(" | "))
      );
      assert(
        audit.findings.some((f) => f.includes(" because ") && f.includes(" and it is now ")),
        c.name + ": the finding must print the cause that was declared AND the cause observed, and it said " + JSON.stringify(audit.findings.join(" | "))
      );
    }

    // THE CONTROL, AND IT IS REQUIRED TO FAIL ON THE RULE IT SUPERSEDES. The old listers return what they
    // found, so the only thing that can be asked of them is whether every vector directory is represented
    // in their output. On a case where a vector yields nothing, it is not, and no count they carry says
    // so. A case where the corpus is complete cannot tell the two rules apart, and that is recorded
    // rather than counted as a pass.
    const old = supersededByListing(tree);
    const seen = new Set([...old.manifests, ...old.runlogs].map((x) => x.vector));
    const everyVectorSeen = survey.vectors.every((v) => seen.has(v.vector));
    if (!everyVectorSeen) supersededTotalityFailures += 1;
    const shippedRefusesOrIsClean = audit.refusals.length > 0 || audit.findings.length > 0;
    assert(
      everyVectorSeen || shippedRefusesOrIsClean,
      c.name + ": the superseded listers dropped a vector and the shipped rule said nothing about it"
    );
  }

  // The control must have failed somewhere, or it was never a control. MEASURED: the cases that hide a
  // vector's run directory or its RUNLOG are the ones where the old listers come back short.
  assert(
    supersededTotalityFailures > 0,
    "the superseded listers were represented in every fixture, so the totality assertion could not have caught the drop it exists for"
  );

  // AND THE REAL TABLES ARE NOT EMPTY, because every assertion above would hold over four empty objects.
  assert(Object.keys(EXPECT_NO_ROOT_MANIFEST).length === 4, "EXPECT_NO_ROOT_MANIFEST names " + Object.keys(EXPECT_NO_ROOT_MANIFEST).length + " vector(s), and the four known-answer vectors are the ones it is for");
  assert(Object.keys(EXPECT_NO_RUNLOG).length === 5, "EXPECT_NO_RUNLOG names " + Object.keys(EXPECT_NO_RUNLOG).length + " vector(s), and it is for the four known-answer vectors plus absent-runlog");
  let declarationsChecked = 0;
  for (const [name, decl] of [...Object.entries(EXPECT_NO_ROOT_MANIFEST), ...Object.entries(EXPECT_NO_RUNLOG), ...Object.entries(EXPECT_RUN_WITHOUT_ROOT_MANIFEST), ...Object.entries(NOT_A_VECTOR)]) {
    declarationsChecked += 1;
    assert(typeof decl?.why === "string" && decl.why.length >= 40, "the declaration for " + JSON.stringify(name) + " must carry a reason, and it reads " + JSON.stringify(decl?.why));
    // AND A CAUSE, because a reason nothing can compare against is prose. The audit refuses a
    // declaration without one, and this says so at the table rather than waiting for a corpus to.
    assert(typeof decl?.cause === "string" && decl.cause.length > 0, "the declaration for " + JSON.stringify(name) + " must name the cause the survey reports, and it reads " + JSON.stringify(decl?.cause));
  }
  // THE VACUITY CONTROL FOR THE SWEEP ABOVE. Four tables that resolved and held nothing would satisfy
  // both assertions inside the loop by never running either, and the loop would report a clean pass
  // over the empty set.
  assert(declarationsChecked > 0, "the declaration sweep resolved four tables and found no declaration to check, so it checked nothing");

  // AND THE COUNT THE SUMMARY PRINTS IS HELD DOWN, all three parts of the clause it appears in. The
  // number itself was wrong for as long as it existed because nothing here could tell it was.
  //
  // THE VACUITY CONTROL COMES FIRST and it is not the same assertion as the count. A recorder that
  // resolved, ran and filed nothing is the shape this repository has been closing all night: the
  // comparison stage would have been deleted or guarded past, the sentence would report zero trees, and
  // "0 assertions failed" would be true of a stage that never ran.
  assert(
    installedTreeDrives > 0,
    "the installed-tree recorder was resolved and filed nothing, so the comparison stage never ran and the count in the summary would describe nothing"
  );
  assert(
    installedTrees.size === 8,
    "the self-test drives compareInstalled over 8 installed trees and the recorder filed " + installedTrees.size + "; if a tree was added or removed on purpose, this number moves with it"
  );
  // DISTINCT IS A CLAIM AND SO IT IS CHECKED. Two call sites handed the same tree would leave the count
  // honest about invocations and dishonest about coverage, which is the same defect one layer along.
  assert(
    installedTreeDrives === installedTrees.size,
    "the comparison stage drove " + installedTreeDrives + " tree(s) and only " + installedTrees.size + " of them differ, so the summary may not call them distinct"
  );
  // THE OTHER HALF OF THE SAME CLAUSE. "none of which exist on disk" was true and was also unpinned: a
  // future tree pointed at a real path would make the comparison stage depend on an install, which is
  // the whole reason probeInstalled is a parameter.
  let fabricatedPaths = 0;
  for (const answers of installedTrees.values()) {
    for (const [name, got] of answers) {
      if (typeof got?.at !== "string") continue;
      fabricatedPaths += 1;
      assert(!fs.existsSync(got.at), "the installed tree for " + name + " names " + JSON.stringify(got.at) + ", and that path EXISTS, so this stage is no longer driven over a corpus that does not exist on disk");
    }
  }
  assert(fabricatedPaths > 0, "no installed tree named a path at all, so the claim that none of them exists on disk was checked against nothing");

  if (fails > 0) {
    console.error("validate --self-test: " + fails + " of " + checks + " assertion(s) failed");
    verdictReached(fails, checks, { canonicalTo: "stderr" });
    process.exit(1);
  }
  console.log(
    "validate --self-test: " +
      checks +
      " assertions passed over " +
      cases.length +
      " lockfile entry shapes, " +
      corpusCases.length +
      " conformance corpora and " +
      installedTrees.size +
      " installed trees, none of which exist on disk. A vector that yields no root manifest, a run directory that holds none, a vector with no RUNLOG and an entry beside the vectors that is not a directory each REFUSE at exit 2 naming what came back empty unless this file declares them with a reason, a declaration the corpus no longer bears out is a finding at exit 1 rather than a silence that grows, a declaration whose silence is still there and whose NAMED CAUSE has changed underneath it is a finding at exit 1 as well, a declaration naming no cause at all is refused because nothing can hold it to one, and the superseded listers are proven to drop a vector on the same fixtures without saying so. An entry the classifier cannot read is a refusal naming the key and the reason rather than a silent skip, npm's own link record for a workspace member is set aside rather than refused, npm's ALIAS record is set aside and names the package the lockfile puts at that directory rather than being compared as a pin of the directory's name, the installed package's own `name` is read and compared so a directory holding another package is a finding rather than a pass, the module main() loads is required to resolve inside the package that was graded, EVERY pinned package is required to resolve its own entry point inside its own directory and not the judge alone, every module this process loaded from the entry point onward, CommonJS and ES alike, is recorded as it loads and required to resolve inside those same directories or to be one of the repository's own files this gate names one by one, with a census that refuses rather than passes when it visited nothing, refuses again when the recorder did not see what the require cache holds, and refuses a third time when the record does not reach back to the entry point itself, because a module loaded before the recorder was armed is in neither the record nor the require cache unless it is CommonJS, every pinned name leaves the comparison through exactly one outcome, every key the classifier is given is filed and the denominator for that is read off the input rather than recomputed with the rule under test, and the same assertions are proven to FAIL on all three superseded rules, the version-only comparison among them: the offset rule differs on " +
      disagreedOffset.size +
      " (" +
      [...disagreedOffset].map((k) => JSON.stringify(k)).join(", ") +
      ") and the drop rule on " +
      disagreedDrop.size +
      " (" +
      [...disagreedDrop].map((k) => JSON.stringify(k)).join(", ") +
      ")"
  );
  verdictReached(0, checks);
}

function main() {
  if (process.argv.includes("--self-test")) {
    selfTest();
    return;
  }

  // First, before the schema is opened or a vector is read: hold ajv to the lockfile. See the header on
  // requirePinnedValidator for why the pin is part of what this file asserts.
  const gradedDirs = requirePinnedValidator();

  // The schema is JSON Schema draft 2020-12, so use ajv's 2020 build (the default ajv export only knows
  // draft-07 and rejects the 2020-12 $schema meta). ajv 8 is CommonJS and assigns the constructor to
  // module.exports with a `default` alias on it, so both spellings are the same function; the fallback is
  // there so a future ajv that ships only the named default still works.
  const ajvModule = requireHere(AJV_MODULE);
  const Ajv = ajvModule.default ?? ajvModule;

  // AND NOW THE QUESTION NO CHECK ABOVE ASKS: what did this process actually load. Everything before this
  // line is about names, versions and where a specifier points. `requireHere.cache` is keyed by the
  // resolved real path of every CommonJS module this process has loaded, so it is the run's own answer
  // rather than a claim about the tree. See loadedModuleVerdict for the two escapes that made it
  // necessary and for why the instrument carries its own positive control.
  const loadedFile = fs.realpathSync(requireHere.resolve(AJV_MODULE));

  // THE RECORDER IS PART OF THE CLAIM, so a node that cannot arm it must not print a containment line.
  // module.registerHooks arrived in node 22.15, and the workflow that runs this asks setup-node for 22,
  // which resolves to the newest 22.x. On anything older the only population available is the require
  // cache, and both bypasses recorded on the recorder above are EXIT 0 against that. Refusing at 2 is
  // could-not-check, which is what this is.
  if (!recorderArmed) {
    console.error("REFUSED: this node has no module.registerHooks, so nothing recorded what the process loaded.");
    console.error("  The require cache on its own is a mutable end state. One `delete require.cache[__filename]` in a");
    console.error("  loaded module, and an `import()` of an ES module, are each EXIT 0 against it, both measured.");
    console.error("\n  REMEDY: run this under node 22.15 or later.");
    verdictSkipped("the load recorder could not be armed, so what this process loaded could not be stated", { canonicalTo: "stderr" });
    process.exit(2);
  }

  // THE PERMITTED LIST IS RESOLVED BEFORE IT IS USED, and a name that is not on disk is a refusal. The
  // census compares resolved real paths, so the list has to be spelled the same way; a path that will not
  // realpath cannot match anything and would go on permitting nothing without saying so.
  const permitted = [];
  const missingOwn = [];
  for (const p of REPO_OWN_LOADS) {
    try {
      permitted.push(fs.realpathSync(p));
    } catch (err) {
      missingOwn.push(p + ": " + err.message);
    }
  }
  if (missingOwn.length > 0) {
    console.error("REFUSED: this file names " + missingOwn.length + " of its own repository's file(s) as permitted to load,");
    console.error("  and they are not on disk, so the census would judge whatever did load without them.");
    for (const m of missingOwn) console.error("    " + m);
    console.error("\n  REMEDY: restore the checkout, or correct REPO_OWN_LOADS to name the files this gate actually runs.");
    console.error("\n  Exit 2 rather than 1: nothing is known to be wrong with the tree, only that this list no longer");
    console.error("  describes it.");
    verdictSkipped("the permitted-load list names files that are not on disk, so the load census could not be stated", { canonicalTo: "stderr" });
    process.exit(2);
  }

  const population = censusPopulation(loadRecord, Object.keys(requireHere.cache), (url) => {
    // The cache spells its keys as resolved real paths, so the record has to be spelled the same way or
    // the two sources cannot be compared. A path that will not resolve is kept rather than dropped: it
    // cannot be inside a graded directory, so keeping it sends it to the comparison instead of to the
    // floor.
    const p = fileURLToPath(url);
    try {
      return fs.realpathSync(p);
    } catch {
      return p;
    }
  });
  if (population.kind === "refuse") {
    console.error("REFUSED: the record of what this process loaded cannot be trusted, so it is not reported.");
    console.error("  " + population.why);
    verdictSkipped("the load record did not hold, so what this process loaded could not be stated", { canonicalTo: "stderr" });
    process.exit(2);
  }

  // BEFORE THE CENSUS IS READ, WHERE ITS POPULATION STARTS. See entryObservedVerdict: this is the only
  // check that can see a load that happened before the recorder was armed through the module system that
  // never touches the require cache.
  const entrySeen = entryObservedVerdict(population.keys, fs.realpathSync(fileURLToPath(import.meta.url)));
  if (entrySeen.kind === "refuse") {
    console.error("REFUSED: the load record does not begin before this file, so it cannot say what this process loaded.");
    console.error("  " + entrySeen.why);
    console.error("\n  REMEDY: run this through `npm run validate` in " + SELF_DIR + ", which is");
    console.error("  `node --import ./arm-load-recorder.mjs validate.mjs`. Running `node validate.mjs` on its own arms");
    console.error("  nothing before this file's own static imports, and a module loaded then is in neither the record");
    console.error("  nor the require cache.");
    verdictSkipped("the load recorder was not armed before this file loaded, so what this process loaded could not be stated", { canonicalTo: "stderr" });
    process.exit(2);
  }

  const loaded = loadedModuleVerdict(population.keys, gradedDirs, loadedFile, permitted);
  if (loaded.kind === "refuse") {
    console.error("REFUSED: the census of what this process loaded cannot be trusted, so it is not reported.");
    console.error("  " + loaded.why);
    verdictSkipped("the loaded-module census did not hold, so what this process loaded could not be stated", { canonicalTo: "stderr" });
    process.exit(2);
  }
  if (loaded.kind === "fail") {
    console.error("FAIL: this process loaded " + loaded.foreign.length + " module(s) from outside every package the lockfile pins.");
    for (const f of loaded.foreign) console.error("    " + f);
    console.error("  The vectors below would have been graded by code this repository does not pin, and the name,");
    console.error("  version and entry-point checks above would all still have been satisfied.");
    console.error("\n  REMEDY: run `npm ci` in " + SELF_DIR + " and re-run. If a pinned package has genuinely grown a");
    console.error("  dependency outside these directories, add it to package.json so the lockfile pins it too.");
    verdictReached(loaded.foreign.length, loaded.total, { canonicalTo: "stderr" });
    process.exit(1);
  }
  console.log(
    "validator code contained: all " +
      loaded.total +
      " module(s) loaded to reach " +
      JSON.stringify(AJV_MODULE) +
      " resolve inside the " +
      loaded.inside.size +
      " graded package directory/directories (" +
      [...loaded.inside].map(([d, n]) => path.basename(d) + " " + n).join(", ") +
      ") or are one of this gate's own " +
      loaded.own.length +
      " named file(s) (" +
      loaded.own.map((p) => path.basename(p)).join(", ") +
      "). CommonJS AND ES, recorded from before this file itself loaded rather than read off the cache afterwards, with " +
      population.builtins.length +
      " node builtin(s) set aside and " +
      population.outsideCache.length +
      " module(s) the cache does not hold."
  );

  // strict: true everywhere, except strictRequired: the ShardRecord if/then
  // requires recordSalt (defined in the parent properties) from inside a
  // conditional applicator, which strictRequired flags even though the property
  // is defined. This is the intended secrets-only modelling of SPEC.md 6.3, so
  // the one sub-check is relaxed while strict schema validation otherwise holds.
  const ajv = new Ajv({ allErrors: true, strict: true, strictRequired: false });
  const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf8"));

  // Compiling is the well-formedness check on the schema itself: a malformed
  // schema throws here.
  let validateTop;
  try {
    validateTop = ajv.compile(schema);
  } catch (err) {
    console.error("SCHEMA NOT WELL-FORMED: " + err.message);
    // The schema did not compile, so no manifest was ever checked against it.
    verdictSkipped("docs/format/schema.json did not compile, so no manifest was checked: " + err.message, { require: true, canonicalTo: "stderr" });
    process.exit(1);
  }
  console.log("schema well-formed: docs/format/schema.json compiled");

  // The named subschemas, addressed by $ref, so a manifest is checked against
  // exactly RootManifest and a RUNLOG line against exactly RunlogEntry rather
  // than the permissive top-level oneOf.
  const validateRoot = ajv.getSchema(schema.$id + "#/$defs/RootManifest");
  const validateRunlog = ajv.getSchema(schema.$id + "#/$defs/RunlogEntry");
  if (!validateRoot || !validateRunlog) {
    console.error("SCHEMA MISSING a required $def (RootManifest / RunlogEntry)");
    verdictSkipped("schema is missing RootManifest or RunlogEntry, so no object could be addressed", { require: true, canonicalTo: "stderr" });
    process.exit(1);
  }

  // THE CORPUS IS SURVEYED BEFORE IT IS VALIDATED, and the survey is refused before a vector is read.
  // See requireDeclaredCoverage: an undeclared empty vector is a could-not-check, and finding that out
  // after printing a hundred `ok` lines would bury it.
  const survey = surveyVectors(realTree);
  if (survey === null) {
    console.error("REFUSED: " + VECTORS_DIR + " could not be listed, so no vector was surveyed.");
    verdictSkipped("the conformance vectors directory could not be listed", { canonicalTo: "stderr" });
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
  // Per-loop tallies, so each loop can be asserted to have accounted for everything it was handed. They
  // are separate from `validated` and `expectedFailures` because those two are corpus-wide.
  let manifestsSeen = 0;
  let runlogElements = 0;
  let runlogTerminators = 0;
  let runlogGraded = 0;
  const failuresBefore = { manifests: 0, runlogs: 0 };

  failuresBefore.manifests = failures.length;
  for (const { vector, file } of manifestsToCheck) {
    manifestsSeen += 1;
    const expectSyntaxInvalid = Object.prototype.hasOwnProperty.call(EXPECT_JSON_SYNTAX_INVALID, vector);
    let data;
    try {
      data = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (err) {
      if (expectSyntaxInvalid) {
        expectedFailures += 1;
        console.log(
          "ok (rejected as designed, not valid JSON syntax): " + rel(file) + " [" + EXPECT_JSON_SYNTAX_INVALID[vector] + "]"
        );
      } else {
        failures.push(rel(file) + ": not parseable JSON: " + err.message);
      }
      continue;
    }
    if (expectSyntaxInvalid) {
      failures.push(
        rel(file) +
          ": EXPECTED to fail JSON.parse (" +
          EXPECT_JSON_SYNTAX_INVALID[vector] +
          ") but it parsed as valid JSON. The vector no longer exercises RFC 8259 syntax rejection."
      );
      continue;
    }
    const ok = validateRoot(data);
    const expectInvalid = Object.prototype.hasOwnProperty.call(EXPECT_SCHEMA_INVALID, vector);

    if (expectInvalid) {
      if (ok) {
        failures.push(
          rel(file) +
            ": EXPECTED to fail the schema (" +
            EXPECT_SCHEMA_INVALID[vector] +
            ") but it validated. The schema is too permissive."
        );
      } else {
        expectedFailures += 1;
        console.log("ok (rejected as designed): " + rel(file) + " [" + EXPECT_SCHEMA_INVALID[vector] + "]");
      }
      continue;
    }

    if (!ok) {
      failures.push(
        rel(file) + ": real/valid manifest FAILED the schema:\n  " + ajv.errorsText(validateRoot.errors, { separator: "\n  " })
      );
    } else {
      validated += 1;
      console.log("ok: " + rel(file));
    }
  }
  const manifestsAccounted = validated + expectedFailures + (failures.length - failuresBefore.manifests);
  if (manifestsAccounted !== manifestsSeen) {
    console.error("REFUSED: " + manifestsSeen + " manifest(s) were handed to the schema loop and " + manifestsAccounted);
    console.error("  came back with an outcome. " + (manifestsSeen - manifestsAccounted) + " reached none, so this check");
    console.error("  cannot say what it found for them. This is an internal inconsistency in the check.");
    verdictSkipped("the manifest loop did not account for every manifest the survey handed it", { canonicalTo: "stderr" });
    process.exit(2);
  }

  failuresBefore.runlogs = failures.length;
  const validatedBeforeRunlogs = validated;
  const expectedBeforeRunlogs = expectedFailures;
  for (const { vector, file } of runlogsToCheck) {
    const rawLines = fs.readFileSync(file, "utf8").split("\n");
    runlogElements += rawLines.length;
    let lineNo = 0;
    for (const raw of rawLines) {
      lineNo += 1;
      // THE FOURTH DROP SITE, AND IT WAS THE ONLY ONE WITH LIVE INSTANCES THAT WERE ALL LEGITIMATE.
      // `if (raw.length === 0) continue` treated every empty split element the same. Splitting a
      // newline-terminated file on "\n" yields one empty element at the END, which is the remainder
      // after the terminator and is not a line at all; an empty element ANYWHERE ELSE is a blank line
      // in a file SPEC.md 10 defines as JSON Lines, and it was leaving by the same door with nothing
      // counting it or naming it. MEASURED across the 48 RUNLOG files: 104 split
      // elements, 56 lines, 48 terminators and no interior blank, so the old rule was right 48 times
      // out of 48 and would have been silent on the 49th.
      if (raw.length === 0) {
        if (lineNo === rawLines.length) {
          runlogTerminators += 1;
          continue;
        }
        failures.push(
          rel(file) +
            " line " +
            lineNo +
            ": blank line in a RUNLOG. SPEC.md 10 defines the RUNLOG as one JSON object per line, and a" +
            " blank line is neither an entry nor the terminating newline (which is element " +
            rawLines.length +
            ")."
        );
        continue;
      }
      runlogGraded += 1;
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
          failures.push(
            rel(file) + " line " + lineNo + ": EXPECTED to fail the schema (" + EXPECT_RUNLOG_LINE_INVALID[key] + ") but it validated."
          );
        } else {
          expectedFailures += 1;
          console.log("ok (rejected as designed): " + rel(file) + " line " + lineNo + " [" + EXPECT_RUNLOG_LINE_INVALID[key] + "]");
        }
        continue;
      }
      if (!ok) {
        failures.push(
          rel(file) + " line " + lineNo + ": RUNLOG entry FAILED the schema:\n  " + ajv.errorsText(validateRunlog.errors, { separator: "\n  " })
        );
      } else {
        validated += 1;
        console.log("ok: " + rel(file) + " line " + lineNo);
      }
    }
  }
  // THE SAME IDENTITY OVER THE RUNLOG LOOP, and the denominator is the number of split elements read off
  // the files rather than the number of lines this loop decided to look at. Every element is a
  // terminator, a validated entry, a negative confirmed rejected, or a failure. Nothing else.
  const runlogAccounted =
    runlogTerminators +
    (validated - validatedBeforeRunlogs) +
    (expectedFailures - expectedBeforeRunlogs) +
    (failures.length - failuresBefore.runlogs);
  if (runlogAccounted !== runlogElements) {
    console.error("REFUSED: the RUNLOG files split into " + runlogElements + " element(s) and " + runlogAccounted);
    console.error("  came back with an outcome (" + runlogTerminators + " terminator(s), " + runlogGraded + " line(s) graded).");
    console.error("  " + (runlogElements - runlogAccounted) + " reached none, so this check cannot say what it found for them.");
    verdictSkipped("the RUNLOG loop did not account for every line it read", { canonicalTo: "stderr" });
    process.exit(2);
  }

  console.log("");
  console.log(
    "validated " +
      validated +
      " structurally valid manifest/RUNLOG objects; " +
      expectedFailures +
      " negative vectors rejected as designed"
  );

  // The population is every object this run actually put through the schema: the manifests and RUNLOG
  // lines that validated, plus the negative vectors it confirmed were rejected. A corpus that yielded
  // none of either checked nothing, and the guard refuses that rather than letting "PASS" stand.
  const examined = validated + expectedFailures;

  if (failures.length > 0) {
    console.error("");
    console.error("FAIL: " + failures.length + " problem(s):");
    for (const f of failures) console.error("  - " + f);
    verdictReached(failures.length, examined);
    process.exit(1);
  }
  console.log("PASS");
  verdictReached(0, examined);
}

main();
