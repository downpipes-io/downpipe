// Generates the cross-implementation fixture for `downpipe verify-report`. The engine's own report code
// (src/admin/reports.ts: makeReport and signReport) builds and signs each report, and the Go tests in
// cmd/downpipe/verify_report_test.go and internal/format/report_test.go verify these exact bytes. If the
// engine changes what it signs, a regenerated fixture fails those tests.
//
// Run with Node 22.18 or later (it imports the engine's TypeScript directly):
//   node internal/format/testdata/signed-report/gen-fixture.mjs <engine-root> internal/format/testdata/signed-report
//
// It writes:
//   signer.pub              the signer's public key file, as the key ceremony saves it
//   other-signer.pub        a second signer's public key file, for the wrong-key cases
//   posture.json            a point-in-time report, exactly as GET /admin/reports/posture returns it
//   posture.pretty.json     the same report as the console's View JSON shows it (two-space indent)
//   posture.canonical       the bytes the engine signed for posture.json
//   restore-tests.json      a windowed report whose strings exercise the canonical JSON rules
//   restore-tests.canonical the bytes the engine signed for restore-tests.json
//   unsigned.json           a report from an engine with no signer configured
//
// The signer seeds are fixed, so signer.pub and other-signer.pub are the same on every run. The ML-DSA-87
// half of each signature draws fresh randomness, so the signatures differ between runs and each run is a
// new, equally valid fixture.

import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [engineRoot, outDir] = process.argv.slice(2);
if (!engineRoot || !outDir) {
  console.error("usage: node gen-fixture.mjs <engine-root> <out-dir>");
  process.exit(1);
}
const load = (rel) => import(pathToFileURL(join(engineRoot, rel)).href);

const { makeReport, signReport } = await load("src/admin/reports.ts");
const { canonicalJSON } = await load("src/format/canonjson.ts");
const { loadSigner, verifierFrom } = await load("src/keys-env.ts");
const { concat, b64urlEncode } = await load("src/crypto/bytes.ts");
const { LABEL_SIGNER_PUBLIC } = await load("src/crypto/keys.ts");

// SIGNER_PRIVATE is ed25519 seed(32) || ML-DSA-87 seed(32), base64url.
const seed = (start) => b64urlEncode(Uint8Array.from({ length: 64 }, (_, i) => (start + i) & 0xff));
const signer = await loadSigner(seed(1));
const other = await loadSigner(seed(101));
const pubFile = (s) => {
  const v = verifierFrom(s);
  return `${LABEL_SIGNER_PUBLIC} ${b64urlEncode(concat(v.ed, v.mldsa))}\n`;
};

// The same projection signReport signs. reports.ts keeps signedView private, so the fixture restates it
// and the Go test compares these bytes with its own canonical form of the report.
const view = (r) => ({ kind: r.kind, generatedAt: r.generatedAt, period: r.period, data: r.data });

// The fixed instant below keeps the fixture stable apart from the ML-DSA-87 randomness.
const now = Date.UTC(2026, 8, 25, 0, 0, 0, 0);

const posture = makeReport(
  "posture",
  {
    score: 87,
    checks: [
      { id: "break-glass-recipient", status: "pass", severity: "critical" },
      { id: "worm-destination", status: "warn", severity: "medium" },
    ],
  },
  null,
  now,
);

// Strings and keys that separate a correct canonical form from a near miss: HTML characters that
// JSON.stringify leaves alone, control characters it escapes, U+2028 and U+2029, a non-BMP character, and
// two keys whose UTF-16 order differs from their code point order (U+1F600 sorts before U+FF61 by UTF-16
// code unit). Integers include a negative, zero and the largest safe integer.
const restoreTests = makeReport(
  "restore-tests",
  {
    recency: [
      {
        id: "dp-kv-prod",
        name: "prod <kv> & \"secrets\" é中😀",
        lastRestoreTestAt: 1790208000000,
        lastRestoreTestOk: true,
        lastRestoreTestKind: "attended",
        lastRestoreTestSampleRate: 100,
        restoreProvenAt: 1790208000000,
        restoreProvenBy: "owner@example.com",
        restoreProvenMethod: "attended-blind-test",
      },
      { id: "dp-d1-billing", name: "billing\tledger line para\u0001\u001f\\", lastRestoreTestDeferred: "no-run" },
    ],
    evidence: [
      { runId: "01K5ZZ0000000000000000000A", kind: "in-account", recordedAt: "2026-09-20T03:00:00.000Z", recordedBy: null },
      { runId: "01K5ZZ0000000000000000000B", kind: "offline-rehearsal", recordedAt: "2026-09-21T03:00:00.000Z", recordedBy: "auditor@example.com", note: "passed / ok" },
    ],
    attendedCadenceDays: 30,
    "｡": -1,
    "😀": 0,
    max: Number.MAX_SAFE_INTEGER,
  },
  { fromSeconds: 1782432000, toSeconds: 1790208000 },
  now,
);

const signedPosture = await signReport(posture, signer);
const signedRestore = await signReport(restoreTests, signer);
const unsigned = makeReport("immutability", { platform: "tamper-evident", worm: null }, null, now);

writeFileSync(join(outDir, "signer.pub"), pubFile(signer));
writeFileSync(join(outDir, "other-signer.pub"), pubFile(other));
writeFileSync(join(outDir, "posture.json"), JSON.stringify(signedPosture));
writeFileSync(join(outDir, "posture.pretty.json"), JSON.stringify(signedPosture, null, 2));
writeFileSync(join(outDir, "posture.canonical"), canonicalJSON(view(signedPosture)));
writeFileSync(join(outDir, "restore-tests.json"), JSON.stringify(signedRestore));
writeFileSync(join(outDir, "restore-tests.canonical"), canonicalJSON(view(signedRestore)));
writeFileSync(join(outDir, "unsigned.json"), JSON.stringify(unsigned));
console.log(`signed-report fixture written to ${outDir}`);
