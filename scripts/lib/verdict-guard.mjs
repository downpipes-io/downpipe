// verdict-guard: the shared completion guard for a repository's script entry points.
//
// THIS FILE IS SHARED VERBATIM across website, control-plane and downpipe, so the measurements below
// name the repository they were taken in. A bare repository-relative path here reads to each
// repository's own citation gate as a claim about ITSELF, and six of them did exactly that when this
// file first arrived in control-plane, which is why every path below carries its repository.
//
// THE CLASS IT CLOSES. An entry point that reaches exit 0 without ever reaching its own verdict, so
// every assertion or every unit of work in the run was structurally incapable of failing. Nothing
// notices, because the only thing anyone checks is the exit code, and the exit code was 0.
//
// FIRST MEASURED IN THE ENGINE. engine/test/validate-destsim-selftest.ts printed 109 assertion lines and
// exited 0: the syslog emulator's stall fault parked an accepted raw socket behind an unref()'d timer,
// so net.Server.close()'s completion callback never fired, the promise wrapping it never settled, Node
// found nothing ref'd holding the event loop open, drained it, and exited 0. The verdict line never
// printed.
//
// MEASURED IN THE WEBSITE REPO, AND LIVE. All three of its PDF generators carried the same shape, and it was
// reproduced rather than inferred, on Node 22.23.1 against a stub DevTools endpoint that answered
// /json/version and /json/list, accepted the WebSocket upgrade, then dropped the socket:
//
//     website/scripts/print-evidence-packs.mjs   EXIT=0  stdout 0 bytes  stderr 0 bytes
//     website/scripts/print-legal-docs.mjs       EXIT=0  stdout 0 bytes  stderr 0 bytes
//     website/scripts/print-evidence-docs.mjs    EXIT=0  stdout 0 bytes  stderr 0 bytes
//
// The cause in all three is one helper:
//
//     const send = (method, params = {}) =>
//       new Promise((resolve) => { pending.set(++nextId, resolve); ws.send(...); });
//
// no reject, no timeout. When the DevTools target goes away mid-run (a crashed or closed Chrome, a
// navigation that never fires Page.loadEventFired, a reply whose id is not in `pending`) the promise
// never settles, the closed socket stops holding the loop, Node drains and exits 0. `npm run
// evidence-packs` then reports success having written no PDFs at all, and the published downloads keep
// whatever bytes were there before.
//
// WHY ONE HOOK IS ENOUGH. Assigning process.exitCode inside an "exit" listener is honoured by Node, and
// it overrides an explicit process.exit(0) that has already been requested (measured on Node 22.23.1).
// So a single "exit" listener catches every way the verdict can be skipped:
//   - the event loop drained while an await was outstanding (the measured case above);
//   - an await on something that never resolves;
//   - a rejection swallowed by an empty .catch(), leaving the verdict unreached;
//   - an early return before the verdict;
//   - a process.exit(0) before the verdict;
//   - a file that only exports its work and never invokes it, so nothing runs at all.
// In all of them the guard was armed and verdictReached() was never called, so the guard fires.
//
// ENROLMENT IS NOT OPTIONAL. scripts/verdict-guard-gate.mjs derives the set of entry points that must be
// enrolled from package.json, the CI workflows and the runner configs, rather than from a list kept by
// hand, and an unenrolled entry point is a gate finding. Do not add a bypass; a guard some entry points
// opt into is the same defect wearing a helmet.
//
// USAGE, two lines:
//   import { verdictReached } from "./lib/verdict-guard.mjs";   // importing this ARMS the guard
//   ...
//   console.log(failures === 0 ? "EXAMPLE PASS" : `${failures} FAILURE(S)`);
//   verdictReached(failures, checks);                           // declare the verdict you just printed
//   process.exit(failures === 0 ? 0 : 1);

/** declared is set by verdictReached()/verdictSkipped(). The exit listener reads it, nothing else writes it. */
let declared = false;
/** the failure count the entry point declared, kept so the guard can back-stop a missing exit(1). */
let declaredFailures = 0;
/** bytes the process has written to stdout since arming, used as the nothing-to-check floor. */
let stdoutBytes = 0;
/** how many verdicts the guard REFUSED. See the exit listener: a refusal has to survive an exit(0). */
let refusals = 0;

/** entryName is only for the message. process.argv[1] is the script node was pointed at. */
const entryName = process.argv[1] ?? "(unknown entry)";

// Counting stdout is how the guard refuses a vacuous pass without asking every entry point to plumb a
// check count through. An entry point that declares a verdict having written nothing at all did not do
// anything. The wrapper is deliberately thin and passes every argument and the return value straight
// through, so it cannot change what a script prints or how it back-pressures: scripts/print-urls-style
// entry points whose stdout is MACHINE READ depend on that, and so does a server whose readiness is
// discovered by pattern-matching its stdout.
const realWrite = process.stdout.write.bind(process.stdout);
/** @param {Parameters<typeof process.stdout.write>} args */
const countingWrite = (...args) => {
  const chunk = args[0];
  stdoutBytes += typeof chunk === "string" ? Buffer.byteLength(chunk) : (chunk?.byteLength ?? 0);
  return realWrite(...args);
};
// The cast is the narrowest one available: process.stdout.write is an overloaded signature and a single
// rest-parameter arrow cannot be assignable to it, while any wrapper that IS assignable would have to
// restate both overloads and could then drop an argument. Passing every argument through unchanged is the
// property that matters here, so the assignment is asserted rather than the wrapper reshaped.
process.stdout.write = /** @type {typeof process.stdout.write} */ (countingWrite);

process.on("exit", (code) => {
  if (declared) {
    // A REFUSED verdict is still a declared one, so the message below does not apply, but the refusal has
    // to STICK. Measured on Node 22.23.1: verdictReached(0, 0) sets process.exitCode = 1 and an explicit
    // process.exit(0) on the next line overrides it, so the guard printed "Forcing exit 1" and the process
    // exited 0 anyway. That is the same false green the guard exists to stop, arriving through the guard.
    // The reference implementation this was ported from has the shape too, and it was found here because
    // website/scripts/gen-cf-surfaces.mjs writes only to stderr and calls process.exit(0) immediately after
    // declaring, so it hit both the stdout floor and this hole in the same run.
    if (refusals > 0 && code === 0) {
      process.stderr.write(
        `\nVERDICT GUARD: ${entryName} had ${refusals} verdict(s) refused and then exited 0.\n` +
          `  An explicit process.exit(0) overrides process.exitCode, so the refusal is re-applied here.\n`,
      );
      process.exitCode = 1;
    }
    return;
  }
  // stderr, not stdout: the counted stream must not be moved by the guard's own message, and a caller
  // that only reads stdout still sees the non-zero exit.
  process.stderr.write(
    `\nVERDICT GUARD: ${entryName} reached process exit with code ${code} without declaring a verdict.\n` +
      `  The verdict was never reached, so nothing in this run was capable of failing.\n` +
      `  Causes seen in this repo: an await on a promise that never settles (a DevTools send() with no\n` +
      `  reject and no timeout, against a target that went away), an early return before the verdict, a\n` +
      `  process.exit(0) before the verdict, a rejection swallowed by an empty catch, or an entry point\n` +
      `  that only exports its work.\n` +
      `  ${stdoutBytes === 0 ? "It wrote nothing at all to stdout, so it did no work.\n" : `It wrote ${stdoutBytes} bytes to stdout before stopping.\n`}` +
      (code === 0 ? "  Forcing exit 1: a silent exit 0 here is a false green.\n" : "  Leaving the non-zero exit code as it stands.\n"),
  );
  if (code === 0) process.exitCode = 1;
});

/**
 * verdictReached declares that the entry point printed its verdict, and is the only thing that disarms
 * the guard. Call it AFTER printing the verdict and BEFORE any exit.
 *
 * @param {number} failures how many checks failed, or how many units of work were not completed. A
 *   positive count sets process.exitCode = 1 even if the caller forgets its own process.exit(1),
 *   because "printed N FAILURE(S) and exited 0" is the same false green by a shorter route.
 * @param {number} [checks] how much was actually checked or done. Zero is a failure: an entry point
 *   that checked nothing is not one that passed. Pass it whenever the count is known, and always pass
 *   it when the verdict itself goes to stderr, because then the stdout floor cannot stand in for it.
 * @param {{ canonicalTo?: "stdout" | "stderr" }} [opts] where to print the one canonical verdict line.
 *   Default stdout. Use "stderr" where stdout is a MACHINE-READ channel: tests/a11y/print-urls.mjs in
 *   the sibling docs repo pipes its stdout straight into an axe-core URL list, so a verdict line on
 *   stdout would be handed to the scanner as a URL, and website/scripts/lh-serve.mjs's stdout is the readiness
 *   channel Lighthouse CI pattern-matches.
 */
export function verdictReached(failures, checks, opts) {
  declared = true;
  declaredFailures = failures;
  if (checks !== undefined && checks <= 0) {
    process.stderr.write(
      `\nVERDICT GUARD: ${entryName} declared a verdict after doing ${checks} unit(s) of work.\n` +
        `  Nothing was checked, so there was nothing to pass. Forcing exit 1.\n`,
    );
    refusals++;
    process.exitCode = 1;
    return;
  }
  if (checks === undefined && stdoutBytes === 0) {
    process.stderr.write(
      `\nVERDICT GUARD: ${entryName} declared a verdict having written nothing to stdout.\n` +
        `  An entry point that printed no result produced none. Forcing exit 1.\n`,
    );
    refusals++;
    process.exitCode = 1;
    return;
  }
  // One canonical line, printed by the guard rather than by each script, so the LOG-READING half of a
  // verification has a fixed anchor too. Reading the exit code is only half the check: a verification
  // grep of `(^|[^a-zA-Z])FAIL` matches nothing under BSD grep on macOS while plain `grep FAIL` found 41
  // lines on the same failing log, so a log-reading check can pass on a failing run just as quietly as
  // an exit code can. Grep this with a FIXED STRING, never a regex: `grep -F "VERDICT: FAIL"`.
  const line = `VERDICT: ${failures === 0 ? "PASS" : "FAIL"} failures=${failures}${checks === undefined ? "" : ` checks=${checks}`} entry=${entryName}\n`;
  if (opts?.canonicalTo === "stderr") process.stderr.write(line);
  else process.stdout.write(line);
  if (failures > 0) process.exitCode = 1;
}

/**
 * verdictSkipped declares that the entry point could not do its work, and why. A skip is a real verdict
 * and must be declared like any other, because "exits 0 having done nothing" is the same false green
 * whether the cause is a hang or a missing precondition.
 *
 * It does NOT force a non-zero exit by default. Some preconditions here are deliberately opt-in (a
 * headless Chrome on the DevTools port, a sibling engine checkout, an optional dev dependency) and
 * those must not turn an ordinary run red. What it does is make the skip DECLARED and greppable on one
 * uniform line, so "did this actually run, or did it skip?" has an answer in the log rather than an
 * inference from a silent exit 0.
 *
 * Pass require: true where the caller has decided the precondition is mandatory in this environment
 * (the REQUIRE_ENGINE convention this repo already uses in ci.yml); the skip then exits 1.
 *
 * @param {string} reason
 * @param {{ require?: boolean, canonicalTo?: "stdout" | "stderr" }} [opts]
 */
export function verdictSkipped(reason, opts) {
  declared = true;
  const line = `\nVERDICT SKIPPED: ${entryName}: ${reason}\n`;
  if (opts?.canonicalTo === "stderr") process.stderr.write(line);
  else process.stdout.write(line);
  if (opts?.require === true) {
    process.stderr.write(`  the precondition was declared mandatory here, so the skip is a failure.\n`);
    refusals++;
    process.exitCode = 1;
  }
}

/** verdictDeclaredFailures exists for the guard's own self-test; nothing else should need it. */
export function verdictDeclaredFailures() {
  return declaredFailures;
}
