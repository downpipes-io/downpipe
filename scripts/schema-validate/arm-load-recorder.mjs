// THE LOAD RECORDER, IN ITS OWN FILE BECAUSE OF WHEN IT HAS TO RUN. validate.mjs's census asks what this
// process loaded. It can only answer for loads the recorder saw, so the recorder has to be armed before
// the first of them, and inside validate.mjs that is not reachable.
//
// WHY NOT AT THE TOP OF validate.mjs, WHICH IS WHERE IT WAS. A static `import` is evaluated BEFORE the
// importing module's body runs, so every statically imported module and everything it imports in turn had
// already loaded by the time an arming statement in that body executed. validate.mjs statically imports
// `../lib/verdict-guard.mjs`, which is not a builtin, so that module and its whole import graph loaded
// with the recorder disarmed.
//
// AND AN UNSEEN ES LOAD IS IN NEITHER HALF OF THE UNION the census reads. A pre-arming CommonJS load is
// still caught, because it sits in the require cache and censusPopulation refuses when the cache holds a
// key the recorder never saw. An ES module never enters the require cache at all, so a pre-arming ES load
// is in no record and in no cache: invisible, not merely unrecorded.
//
// MEASURED in downpipe, exit code read off the process rather than through a pipe. One
// line, `import "../foreign-preload.mjs";`, added to downpipe/scripts/lib/verdict-guard.mjs: the run was
// EXIT 0, VERDICT PASS at 112 checks, the census printed the same "all 88 module(s)" a clean tree prints,
// and the foreign file had written a marker naming this process's pid and argv[1]. That is the same
// reading, line for line, that the two bypasses closed the day before produced.
//
// THE ARMING WAS THE HOLE, NOT THE ARMING LINE'S POSITION. Moving the statement earlier in validate.mjs
// closes this one import and leaves the next one open, and a remedy narrower than its own hole is what
// that file has now bought twice. An `--import` preload has no arming line to be above: this module is
// fully evaluated before the entry point is even fetched, so the entry point ITSELF is recorded, and
// validate.mjs refuses rather than reports when it cannot find itself in the record. See
// REPO_OWN_LOADS and entryObservedVerdict in validate.mjs.
//
// IT IMPORTS ONLY A BUILTIN, deliberately. Anything this file imports loads before it arms, and a builtin
// cannot be a file this repository ships.
import nodeModule from "node:module";

// Filed in load order. Nothing here decides anything: deciding is censusPopulation's job, over the whole
// record, where `--self-test` can drive it.
export const loadRecord = [];

// module.registerHooks arrived in node 22.15. On anything older there is no synchronous load hook, and
// validate.mjs refuses at exit 2 rather than falling back to the require cache, which both of the
// bypasses closed are EXIT 0 against.
export const recorderArmed = typeof nodeModule.registerHooks === "function";

if (recorderArmed) {
  nodeModule.registerHooks({
    load(url, context, nextLoad) {
      // FILED BEFORE THE LOAD IS DELEGATED, so a module that throws on evaluation is still recorded as
      // having been reached, and so is one that deletes its own require-cache entry afterwards.
      loadRecord.push(url);
      return nextLoad(url, context);
    },
  });
}
