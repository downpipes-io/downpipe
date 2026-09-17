// Action-pin comment gate.
//
// Every `uses:` in this repo is pinned to a 40-hex commit sha with a trailing comment naming the
// release, because a bare sha is unreadable. The comment is the only thing a human reads, so a
// comment that disagrees with its sha is worse than no comment: it is a check that looks right and
// asserts nothing. This gate resolves each pinned sha against the GitHub ref graph and fails when the
// comment names a release the sha is not.
//
// THE DOWNGRADE TRAP, AND WHY THIS FILE IS SHAPED THE WAY IT IS.
// `actions/setup-node@48b55a01...` is v6.4.0 and was commented `# v4` at roughly 69 sites across the
// estate. The obvious repair, moving the sha to match the comment, resolves `refs/tags/v4` to
// 49933ea5... and silently downgrades every workflow by two majors. So resolving a comment to a sha
// and resolving a sha to a version are NOT interchangeable, and a tool that emits the first will get
// its output pasted into a workflow file.
//
// Two structural defences, both enforced in code rather than by convention:
//
//   1. NO VERSION-TO-SHA RESOLVER EXISTS FOR OUTPUT. The resolver interface below exposes
//      listTagRefs / peelTagObject / commitExists / refForVersion. Only refForVersion takes a version,
//      it is used solely as a yes/no confirmation on the PASS path, and its result is never carried
//      into a message. Every diagnostic is built from versionsForSha(), which returns tag NAMES.
//   2. THE SHA EGRESS FILTER. emit() refuses to print any 40-hex token that is not either the sha
//      already written in the file or the peel of that sha. A comment-derived sha therefore cannot
//      reach the operator even through a message someone adds later. See assertNoForeignSha().
//
// Peeling the pinned sha IS allowed to produce a sha, because it is derived from the pin and not from
// the comment, and it is zero-behaviour-change by construction: an annotated tag object and the commit
// it peels to check out the same tree.
//
// COMMENTS AS DATA: THE THIRD CASE.
// Six scanners in this campaign were found reading comments as code. The rule that came out of it is
// strip comments for MUST-BE-PRESENT checks, do not strip for MUST-BE-ABSENT. This gate is neither:
// the comment IS its subject. So the parse splits each line into a code side and a comment side at the
// first `#` preceded by whitespace, and then:
//   - a WHOLE-LINE comment is not a pin at all and is discarded before counting (the MUST-BE-PRESENT
//     rule: a commented-out `uses:` must not inflate reach or be graded);
//   - on a live line, the code side is graded as code and the comment side as data, and neither is
//     searched for the other's content. In particular the version is read only from the comment side,
//     so `uses: foo/bar@<sha>` with a `v4` elsewhere on the line cannot be mistaken for a claim.
//
// WHAT THIS GATE CANNOT SEE. Written here rather than in a report, because a report is not read at the
// moment someone is deciding whether a green run means what they think it means.
//
//   1. WHETHER THE RELEASE IS TRUSTWORTHY. Everything below grades the label against the tin. A sha
//      correctly labelled v4.6.2 still contains whatever the publisher put in v4.6.2, and an upstream
//      account takeover that publishes a fresh tag on fresh code passes every check here. The floor map
//      slows that down, it does not stop it. Read the diff of a bump; the gate only proves the comment.
//   2. A DOCKER OR LOCAL `uses:`. `docker://image@digest` and `./.github/actions/thing` are counted and
//      set aside, never graded. A docker digest is not resolved against anything at all, so a moved or
//      poisoned image tag is invisible. A local action IS partly covered, because the walk reads every
//      YAML under `.github/`, so a composite action's own pins are graded as ordinary pins.
//   3. ANYTHING OUTSIDE `.github/`. A workflow shipped in a subdirectory, a template, or a doc snippet
//      that someone will paste is not scanned.
//   4. WHETHER A CLAIMED TAG EXISTS. This is a REFUSAL, not an oversight. Confirming "the comment says
//      v3.7.0 and there is no such tag" is the comment-to-sha direction, and no message here is allowed
//      to be built from it (see defence 1 below). A comment naming a tag that does not exist is instead
//      reported as COMMENT-DISAGREES or NAMED-BY-NO-REF, naming the tags the SHA really carries, which
//      is the information a correction can safely be made from.
//   5. A FORK OR TYPOSQUAT, except through the floor map. `attacker/checkout@<honest sha> # v7.0.1`
//      resolves honestly against `attacker/checkout` and every version check passes. What catches it is
//      NO-FLOOR: the floor map is keyed by full `owner/repo`, so an action nobody recorded fails. That
//      makes the floor map an ALLOW-LIST as much as a downgrade floor, and it is the reason a new action
//      may not be added without a manifest entry in the same commit.
//   6. AN UPSTREAM TAG MOVED AFTER THIS RUN. The answer is true when read and is not cached against
//      later force-pushes upstream. Only re-running the gate re-establishes it.
//
// Usage:
//   node scripts/action-pin-comment-gate.mjs               grade this repo, exit non-zero on any finding
//   node scripts/action-pin-comment-gate.mjs --self-test    offline fixtures, no network, no token
//   node scripts/action-pin-comment-gate.mjs --census       print the parsed pins and exit 0
//   node scripts/action-pin-comment-gate.mjs --workspace    report on sibling repos too (never gating)
//
// Exit codes: 0 clean, 1 findings, 2 the gate could not run (no token, network, unreadable input).

import { execFileSync, spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
// Importing this ARMS the completion guard: an exit that never declares a verdict is forced non-zero,
// so a return path added later cannot exit 0 having graded nothing. Every return below declares, and
// the exit-2 paths declare a SKIP rather than a pass, because "could not resolve" is not "resolved".
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const MANIFEST_PATH = join(HERE, "action-pin-manifest.json");

const ARGS = new Set(process.argv.slice(2));
const SELF_TEST = ARGS.has("--self-test");
const CENSUS = ARGS.has("--census");
const WORKSPACE = ARGS.has("--workspace");

const HEX40 = /\b[0-9a-f]{40}\b/g;

// ---------------------------------------------------------------------------------------------
// Output, with the sha egress filter.
// ---------------------------------------------------------------------------------------------

/** Shas this run is permitted to print: the ones already in the files, plus their own peels. */
const shaAllowList = new Set();

export function assertNoForeignSha(message, allow = shaAllowList) {
	for (const token of String(message).match(HEX40) ?? []) {
		if (!allow.has(token)) {
			throw new Error(
				`action-pin gate refused to print a sha it did not derive from a pin: ${token.slice(0, 8)}... ` +
					"A sha reached the output that came from somewhere other than the file or its own peel, " +
					"which is how the downgrade trap gets handed to an operator.",
			);
		}
	}
	return message;
}

const out = [];
function emit(message) {
	out.push(assertNoForeignSha(message));
}
function flush(stream = "error") {
	for (const line of out) (stream === "out" ? console.log : console.error)(line);
	out.length = 0;
}

// ---------------------------------------------------------------------------------------------
// Parsing. Code side and comment side, kept apart.
// ---------------------------------------------------------------------------------------------

/**
 * Split one workflow line into its `uses:` code side and its comment side.
 * Returns null when the line is not a live `uses:` step.
 */
export function parseUsesLine(line) {
	if (/^\s*#/.test(line)) return null; // whole-line comment: not a pin, and must not count towards reach
	const m = line.match(/^\s*(?:-\s+)?uses:\s*(.+?)\s*$/);
	if (!m) return null;
	const rest = m[1];
	const hash = rest.search(/(?:^|\s)#/);
	const codeRaw = (hash >= 0 ? rest.slice(0, hash) : rest).trim();
	const commentRaw = hash >= 0 ? rest.slice(hash).replace(/^\s*#\s?/, "").trim() : null;
	const code = codeRaw.replace(/^["']|["']$/g, "");
	if (code === "") return null;
	return { code, comment: commentRaw };
}

/** Read a version claim out of the comment side only. Returns null when the comment names none. */
export function versionClaimFromComment(comment) {
	if (comment === null || comment === undefined) return null;
	const m = comment.match(/(?:^|\s)v?(\d+(?:\.\d+){0,2})(?=$|[\s,;)]|\b)/);
	return m ? m[1] : null;
}

/** Normalise a tag name to a bare dotted version, or null when it is not a version tag. */
export function tagToVersion(ref) {
	const name = ref.replace(/^refs\/tags\//, "");
	const m = name.match(/^v?(\d+(?:\.\d+){0,2})$/);
	return m ? m[1] : null;
}

export function compareVersions(a, b) {
	const pa = a.split(".").map(Number);
	const pb = b.split(".").map(Number);
	for (let i = 0; i < 3; i += 1) {
		const d = (pa[i] ?? 0) - (pb[i] ?? 0);
		if (d !== 0) return d < 0 ? -1 : 1;
	}
	return 0;
}

/** True when the claim is satisfied by the tag, allowing `4` to stand for `4.x.y`. */
export function claimSatisfiedBy(claim, version) {
	const c = claim.split(".");
	const v = version.split(".");
	if (c.length > v.length) return false;
	return c.every((part, i) => part === v[i]);
}

function listWorkflowFiles(repoRoot) {
	const dir = join(repoRoot, ".github");
	if (!existsSync(dir)) return [];
	const found = [];
	const walk = (d) => {
		for (const entry of readdirSync(d)) {
			if (entry.startsWith(".")) continue; // a hidden directory (.git, an IDE's own folder) is not part of this tree
			const p = join(d, entry);
			const st = statSync(p);
			if (st.isDirectory()) walk(p);
			else if (/\.ya?ml$/.test(entry)) found.push(p);
		}
	};
	walk(dir);
	return found.sort();
}

/**
 * Extract every pin in a repo. Returns { pins, unpinned, local, filesWithUses }.
 * `unpinned` is a finding in its own right: a `uses:` on a tag is not a pin.
 */
export function extractPins(repoRoot) {
	const pins = [];
	const unpinned = [];
	const local = [];
	const filesWithUses = new Map();
	for (const file of listWorkflowFiles(repoRoot)) {
		const text = readFileSync(file, "utf8");
		const lines = text.split("\n");
		let liveUses = 0;
		let parsed = 0;
		for (let i = 0; i < lines.length; i += 1) {
			const line = lines[i] ?? "";
			if (/^\s*#/.test(line)) continue;
			if (/(?:^|\s)uses:\s*\S/.test(line)) liveUses += 1;
			const p = parseUsesLine(line);
			if (!p) continue;
			const at = { file: relative(repoRoot, file), line: i + 1, comment: p.comment };
			if (p.code.startsWith("./") || p.code.startsWith("docker://")) {
				local.push({ ...at, code: p.code });
				parsed += 1;
				continue;
			}
			const m = p.code.match(/^([^/]+\/[^/@]+)((?:\/[^@]+)?)@(.+)$/);
			if (!m) {
				unpinned.push({ ...at, code: p.code, why: "not owner/repo@ref" });
				continue;
			}
			const [, action, subpath, ref] = m;
			if (!/^[0-9a-f]{40}$/.test(ref)) {
				unpinned.push({ ...at, code: p.code, why: `ref ${JSON.stringify(ref)} is not a 40-hex sha` });
				continue;
			}
			pins.push({ ...at, action, subpath, sha: ref, claim: versionClaimFromComment(p.comment) });
			parsed += 1;
		}
		if (liveUses > 0) filesWithUses.set(relative(repoRoot, file), { liveUses, parsed });
	}
	return { pins, unpinned, local, filesWithUses };
}

/**
 * Recorded pinning exceptions. One real case exists in the estate: the SLSA generator must be pinned by
 * TAG, because slsa-verifier refuses provenance minted from a sha-pinned generator ref. An exception is
 * a decision on the record, keyed by action so it survives line moves, and a DEAD exception is itself a
 * finding: an exemption that matches nothing is another comment that lies.
 */
export function applyUnpinnedExceptions(unpinned, exceptions) {
	const used = new Set();
	const reported = [];
	for (const u of unpinned) {
		const key = Object.keys(exceptions).find((k) => u.code.startsWith(k));
		if (key) used.add(key);
		else reported.push(u);
	}
	return { reported, dead: Object.keys(exceptions).filter((k) => !used.has(k)) };
}

// ---------------------------------------------------------------------------------------------
// Resolution. There is no version-to-sha function whose result can reach the output.
// ---------------------------------------------------------------------------------------------

function token() {
	const fromEnv = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || "";
	if (fromEnv) return fromEnv;
	return "";
}

/**
 * An unresolvable ref graph is a FAILURE and never a pass, and main() tells that apart from a grading
 * finding by this flag. Built with Object.assign so the flag is part of the value's type: bolting a
 * property onto a plain Error leaves the reader in main() unchecked, which is how the flag could be
 * renamed on one side only and the exit-2 path would quietly stop firing.
 * @param {string} message
 * @returns {Error & { unreachable: boolean }}
 */
function unreachableError(message) {
	return Object.assign(new Error(message), { unreachable: true });
}

/**
 * @param {string} path
 * @param {string} tok
 * @returns {Promise<{ missing: true, status: number, body?: undefined, link?: undefined } | { missing?: false, status?: undefined, body: unknown, link: string }>}
 */
async function api(path, tok) {
	const url = `https://api.github.com${path}`;
	let res;
	try {
		res = await fetch(url, {
			headers: {
				accept: "application/vnd.github+json",
				"user-agent": "downpipes-action-pin-gate",
				"x-github-api-version": "2022-11-28",
				...(tok ? { authorization: `Bearer ${tok}` } : {}),
			},
		});
	} catch (cause) {
		// Unreachable is a FAILURE, never a pass. This is the whole point of the exit-2 path.
		throw unreachableError(`network failure reaching ${url}: ${cause instanceof Error ? cause.message : String(cause)}`);
	}
	if (res.status === 404 || res.status === 422) return { missing: true, status: res.status };
	if (!res.ok) throw unreachableError(`GitHub API ${res.status} for ${path}`);
	const link = res.headers.get("link") ?? "";
	return { body: await res.json(), link };
}

export function makeLiveResolver(tok) {
	const tagCache = new Map();
	const peelCache = new Map();
	const lsCache = new Map();
	return {
		/** sha -> ref rows via git, peels included. Returns null when git cannot answer. */
		lsRemoteTags(action) {
			if (lsCache.has(action)) return lsCache.get(action);
			let rows = null;
			try {
				const raw = execFileSync("git", ["ls-remote", "--tags", `https://github.com/${action}`], {
					encoding: "utf8",
					timeout: 60_000,
					stdio: ["ignore", "pipe", "ignore"],
				});
				rows = raw
					.split("\n")
					.map((l) => l.split("\t"))
					.filter((c) => c.length === 2)
					.map((c) => ({ sha: (c[0] ?? "").trim(), ref: (c[1] ?? "").replace(/\^\{\}$/, "") }));
			} catch {
				rows = null;
			}
			lsCache.set(action, rows);
			return rows;
		},
		async listTagRefs(action) {
			if (tagCache.has(action)) return tagCache.get(action);
			const acc = [];
			/** @type {string | null} */
			let path = `/repos/${action}/git/matching-refs/tags?per_page=100`;
			for (let page = 1; path && page <= 30; page += 1) {
				const r = await api(path, tok);
				if (r.missing) break;
				const rows = /** @type {{ ref: string, object: { type: string, sha: string } }[]} */ (r.body);
				acc.push(...rows.map((x) => ({ ref: x.ref, type: x.object.type, sha: x.object.sha })));
				const next = /<https:\/\/api\.github\.com([^>]+)>;\s*rel="next"/.exec(r.link ?? "");
				path = next?.[1] ?? null;
			}
			tagCache.set(action, acc);
			return acc;
		},
		async peelTagObject(action, sha) {
			const key = `${action}@${sha}`;
			if (peelCache.has(key)) return peelCache.get(key);
			const r = await api(`/repos/${action}/git/tags/${sha}`, tok);
			const tagObject = /** @type {{ tag: string, object: { sha: string, type: string } }} */ (r.body);
			const v = r.missing ? null : { tag: tagObject.tag, commit: tagObject.object.sha, type: tagObject.object.type };
			peelCache.set(key, v);
			return v;
		},
		async commitExists(action, sha) {
			const r = await api(`/repos/${action}/commits/${sha}`, tok);
			return !r.missing;
		},
		/** PASS-PATH CONFIRMATION ONLY. The returned sha is compared and discarded, never printed. */
		async refForVersion(action, version) {
			for (const name of [`v${version}`, version]) {
				const r = await api(`/repos/${action}/git/ref/tags/${encodeURIComponent(name)}`, tok);
				if (r.missing) continue;
				const refRow = /** @type {{ object: { type: string, sha: string } }} */ (r.body);
				if (refRow.object.type === "tag") {
					const peeled = await this.peelTagObject(action, refRow.object.sha);
					if (peeled) return { tag: name, sha: peeled.commit, tagObject: refRow.object.sha };
				}
				return { tag: name, sha: refRow.object.sha, tagObject: null };
			}
			return null;
		},
	};
}

/** sha -> the tag names that point at it. The only enumeration whose result reaches a message. */
export async function versionsForSha(resolver, action, sha) {
	// Fast path: one `git ls-remote --tags` returns every tag AND its peel, so a repo with 966 tag refs
	// costs one network call instead of ~480 peel requests. Pure enumeration, sha in and tag names out,
	// so the direction that matters is unchanged. Falls back to the REST peel loop when git is absent.
	if (resolver.lsRemoteTags) {
		const table = resolver.lsRemoteTags(action);
		if (table) return [...new Set(table.filter((r) => r.sha === sha).map((r) => r.ref))].sort();
	}
	const refs = await resolver.listTagRefs(action);
	const names = new Set();
	for (const r of refs) if (r.type === "commit" && r.sha === sha) names.add(r.ref);
	const annotated = refs.filter((r) => r.type === "tag");
	const limit = 8;
	let idx = 0;
	const worker = async () => {
		while (idx < annotated.length) {
			const r = annotated[idx];
			idx += 1;
			const peeled = await resolver.peelTagObject(action, r.sha);
			if (peeled && peeled.commit === sha) names.add(r.ref);
		}
	};
	await Promise.all(Array.from({ length: Math.min(limit, annotated.length) }, worker));
	return [...names].sort();
}

// ---------------------------------------------------------------------------------------------
// Grading.
// ---------------------------------------------------------------------------------------------

/** @returns {Promise<{code:string,detail:string}|null>} null when the pin is sound. */
async function gradePin(resolver, pin, floors, opts = {}) {
	shaAllowList.add(pin.sha);

	if (pin.comment === null) {
		return { code: "NO-COMMENT", detail: `${pin.action}@${pin.sha} carries no comment, so nothing states which release it is.` };
	}
	if (pin.claim === null) {
		return {
			code: "NO-VERSION-IN-COMMENT",
			detail: `${pin.action}@${pin.sha} is commented ${JSON.stringify(pin.comment)}, which names no release.`,
		};
	}

	// Fast confirmation. A yes here is a yes; a no falls through to sha-first enumeration, which is the
	// only path that builds a message.
	let confirmed = false;
	const ref = await resolver.refForVersion(pin.action, pin.claim);
	if (ref && ref.sha === pin.sha) confirmed = true;

	let names = [];
	if (!confirmed) {
		names = await versionsForSha(resolver, pin.action, pin.sha);
		confirmed = names.some((n) => {
			const v = tagToVersion(n);
			return v !== null && claimSatisfiedBy(pin.claim, v);
		});
	}

	if (!confirmed) {
		if (names.length === 0) {
			// Nothing names this sha. Two sub-cases, and they need different words.
			const asTagObject = await resolver.peelTagObject(pin.action, pin.sha);
			if (asTagObject) {
				shaAllowList.add(asTagObject.commit);
				return {
					code: "PIN-IS-TAG-OBJECT",
					detail:
						`${pin.action}@${pin.sha} is an ANNOTATED TAG OBJECT, not a commit. ` +
						`GitHub returns 422 "No commit found for SHA" for it, and it survives only because the tarball still resolves. ` +
						`It peels to tag ${asTagObject.tag} at commit ${asTagObject.commit}. ` +
						"The zero-behaviour-change correction is to pin that peeled commit and comment it with the tag it peels to.",
				};
			}
			const exists = await resolver.commitExists(pin.action, pin.sha);
			if (!exists) {
				return {
					code: "UNRESOLVABLE",
					detail: `${pin.action}@${pin.sha} resolves to no commit and no tag object. It cannot be graded, so it fails.`,
				};
			}
			return {
				code: "NAMED-BY-NO-REF",
				detail:
					`${pin.action}@${pin.sha} is a real commit that no tag points at, so the comment ${JSON.stringify(pin.comment)} ` +
					"cannot be true of it. Re-pin to a released commit and comment it with that release.",
			};
		}
		return {
			code: "COMMENT-DISAGREES",
			detail:
				`${pin.action}@${pin.sha} is commented ${JSON.stringify(pin.comment)} but the sha is tagged ` +
				`${names.map((n) => n.replace("refs/tags/", "")).join(", ")}. ` +
				"THE SAFE REPAIR IS TO MOVE THE COMMENT TO THE TAGS NAMED ABOVE, AND TO LEAVE THE SHA WHERE IT IS. " +
				"The sha is what the runner executes and the comment is only what a reader believes, so editing the " +
				"comment changes a belief while editing the sha changes the build. " +
				"That direction is not a style preference. The signing step in the downpipe repo carried this exact " +
				"disagreement: sigstore/cosign-installer was commented v3.7.0 on a sha that is really v3.8.1, and the " +
				"tidy-looking repair, moving the sha down to the tag the comment named, would have downgraded the " +
				"release signer by a minor version while reading in review as though it fixed something. " +
				"If you have decided the comment is right and the pin should genuinely move, that is a version change " +
				"and not a comment fix: make it as its own change, naming the release you are moving to and why, and " +
				"lower the floor in scripts/action-pin-manifest.json in the same commit.",
		};
	}

	// Floors are a PER-REPO policy record, so the sibling report does not apply this repo's floors to
	// another repo's tree. Everything above this line is repo-independent fact and still applies there.
	if (opts.skipFloor) return null;
	// Downgrade floor. A pin that resolves below the floor recorded for its action fails even when the
	// comment is honest, which is exactly the shape of a downgrade disguised as a correction.
	const floor = floors[pin.action];
	if (floor === undefined) {
		return {
			code: "NO-FLOOR",
			detail: `${pin.action} has no floor recorded in scripts/action-pin-manifest.json, so a downgrade of it would not be caught.`,
		};
	}
	// The floor is compared against the HIGHEST version tag on the sha, not against the claim. A
	// partial claim such as `# v6` would otherwise compare as 6.0.0 and read as a downgrade from a
	// 6.4.0 floor, so a partial claim forces the enumeration the fast path skipped.
	if (names.length === 0 && pin.claim.split(".").length < 3) names = await versionsForSha(resolver, pin.action, pin.sha);
	if (names.length === 0) names = [`refs/tags/v${pin.claim}`];
	const resolved = names
		.map(tagToVersion)
		.filter((v) => v !== null)
		.sort(compareVersions)
		.pop();
	if (resolved !== undefined && compareVersions(resolved, floor) < 0) {
		return {
			code: "DOWNGRADE",
			detail:
				`${pin.action}@${pin.sha} resolves to ${resolved}, which is below the recorded floor ${floor}. ` +
				"A pin may not move backwards. If the drop is deliberate, lower the floor in the same commit and say why.",
		};
	}
	return null;
}

// ---------------------------------------------------------------------------------------------
// CI wiring self-check. "Runs in a job nothing can skip it from" is asserted, not asserted-about.
// ---------------------------------------------------------------------------------------------

/**
 * An `if:` is a way for the gate not to run, with exactly two exceptions. `always()` and `!cancelled()`
 * BROADEN a condition rather than narrow it: they are the standard way to say "run this even though an
 * earlier step failed", which is the opposite of skippable, and a gate that refused them would push
 * authors towards the plain form, where an earlier red hides the gate entirely. Everything else is a
 * finding, including a condition that merely CONTAINS always(), because `always() && <anything>` narrows
 * on the right-hand side. Whitespace and a `${{ }}` wrapper are stripped; nothing else is tolerated.
 */
export function ifConditionIsBroadening(expression) {
	const bare = String(expression)
		.trim()
		.replace(/^\$\{\{\s*/, "")
		.replace(/\s*\}\}$/, "")
		.replace(/\s+/g, "");
	return bare === "always()" || bare === "!cancelled()";
}

export function checkCiWiring(ciYamlText, invocation) {
	const problems = [];
	if (!ciYamlText.includes(invocation)) {
		problems.push(`no step in ci.yml runs ${invocation}`);
		return problems;
	}
	// Find the job that contains the invocation by walking back to the last 2-space job key.
	const lines = ciYamlText.split("\n");
	const hit = lines.findIndex((l) => l.includes(invocation));
	let jobStart = -1;
	let jobName = null;
	for (let i = hit; i >= 0; i -= 1) {
		const m = lines[i].match(/^ {2}([A-Za-z0-9_-]+):\s*$/);
		if (m) {
			jobStart = i;
			jobName = m[1];
			break;
		}
	}
	if (jobName === null) {
		problems.push(`could not identify the job containing ${invocation}`);
		return problems;
	}
	let jobEnd = lines.length;
	for (let i = jobStart + 1; i < lines.length; i += 1) {
		if (/^ {2}[A-Za-z0-9_-]+:\s*$/.test(lines[i])) {
			jobEnd = i;
			break;
		}
	}
	const body = lines.slice(jobStart, jobEnd).join("\n");
	for (const line of body.split("\n")) {
		const m = line.match(/^ {4}if:\s*(.+?)\s*$/);
		if (m && !ifConditionIsBroadening(m[1]))
			problems.push(`job ${jobName} carries a job-level if: (${m[1]}), so it can be skipped`);
	}
	if (/^\s{4}continue-on-error:\s*true/m.test(body)) problems.push(`job ${jobName} is continue-on-error, so it cannot fail the run`);
	const stepIdx = body.split("\n").findIndex((l) => l.includes(invocation));
	const stepBlock = body.split("\n").slice(Math.max(0, stepIdx - 4), stepIdx + 1).join("\n");
	for (const line of stepBlock.split("\n")) {
		const m = line.match(/^\s*(?:- )?if:\s*(.+?)\s*$/);
		if (m && !ifConditionIsBroadening(m[1]))
			problems.push(`the step running ${invocation} carries an if: (${m[1]}), so it can be skipped`);
	}
	if (/continue-on-error:\s*true/.test(stepBlock)) problems.push(`the step running ${invocation} is continue-on-error`);
	const successNeeds = /ci-success:[\s\S]*?needs:\s*\[([^\]]*)\]/.exec(ciYamlText);
	if (!successNeeds) problems.push("ci-success has no needs list to read");
	else if (!(successNeeds[1] ?? "").split(",").map((s) => s.trim()).includes(jobName))
		problems.push(`job ${jobName} is not in ci-success needs, so its failure would not block`);
	return problems;
}

// ---------------------------------------------------------------------------------------------
// Self-test: offline fixtures, no token, no network.
// ---------------------------------------------------------------------------------------------

function stubResolver() {
	// A miniature ref graph with all four real shapes in it.
	const graph = {
		"actions/setup-node": {
			tags: [
				{ ref: "refs/tags/v6.4.0", type: "commit", sha: "a".repeat(40) },
				{ ref: "refs/tags/v6", type: "commit", sha: "a".repeat(40) },
				{ ref: "refs/tags/v4.4.0", type: "commit", sha: "b".repeat(40) },
				{ ref: "refs/tags/v4", type: "commit", sha: "b".repeat(40) },
			],
			tagObjects: {},
			commits: new Set(["a".repeat(40), "b".repeat(40), "c".repeat(40)]),
		},
		"vendor/annotated": {
			tags: [{ ref: "refs/tags/v3.36.2", type: "tag", sha: "d".repeat(40) }],
			tagObjects: { ["d".repeat(40)]: { tag: "v3.36.2", commit: "e".repeat(40), type: "commit" } },
			commits: new Set(["e".repeat(40)]),
		},
	};
	return {
		graph,
		async listTagRefs(action) {
			return graph[action]?.tags ?? [];
		},
		async peelTagObject(action, sha) {
			return graph[action]?.tagObjects[sha] ?? null;
		},
		async commitExists(action, sha) {
			return graph[action]?.commits.has(sha) ?? false;
		},
		async refForVersion(action, version) {
			const g = graph[action];
			if (!g) return null;
			for (const name of [`v${version}`, version]) {
				const t = g.tags.find((x) => x.ref === `refs/tags/${name}`);
				if (!t) continue;
				if (t.type === "tag") {
					const p = g.tagObjects[t.sha];
					return p ? { tag: name, sha: p.commit, tagObject: t.sha } : null;
				}
				return { tag: name, sha: t.sha, tagObject: null };
			}
			return null;
		},
	};
}

async function selfTest() {
	const r = stubResolver();
	const floors = { "actions/setup-node": "6.4.0", "vendor/annotated": "3.36.2" };
	const cases = [];
	const check = (name, ok, extra = "") => {
		cases.push({ name, ok, extra });
		console.log(`${ok ? "  ok  " : "  FAIL"} ${name}${extra ? ` (${extra})` : ""}`);
	};

	const pin = (over) => ({ file: "f.yml", line: 1, action: "actions/setup-node", subpath: "", ...over });

	// Parser: the three comment cases.
	check("whole-line comment is not a pin", parseUsesLine(`      # - uses: a/b@${"a".repeat(40)} # v6.4.0`) === null);
	// Optional chaining rather than a non-null assertion: a parse that returns null must FAIL these
	// checks, and `null?.code === <string>` is false, so the polarity is the one we want.
	const live = parseUsesLine(`      - uses: a/b@${"a".repeat(40)} # v6.4.0`);
	check("live line splits code from comment", live?.code === `a/b@${"a".repeat(40)}` && live?.comment === "v6.4.0");
	check("version is read from the comment side only", versionClaimFromComment(null) === null);
	const noHash = parseUsesLine("      - uses: a/b@v4");
	check("a bare tag ref parses with no comment", noHash !== null && noHash.comment === null);

	// Grading, one per class.
	let g = await gradePin(r, pin({ sha: "a".repeat(40), comment: "v6.4.0", claim: "6.4.0" }), floors);
	check("honest pin passes", g === null, g?.code);

	g = await gradePin(r, pin({ sha: "a".repeat(40), comment: "v6", claim: "6" }), floors);
	check("a partial claim is graded on the sha's highest tag, not read as a downgrade", g === null, g?.code);

	g = await gradePin(r, pin({ sha: "a".repeat(40), comment: "v4", claim: "4" }), floors);
	check("ATTACK 1 lying comment is caught", g?.code === "COMMENT-DISAGREES", g?.code);
	// Bound once outside the closure: `g` is nullable and the narrowing would not survive into it. A
	// null grading yields "", which fails the regex and short-circuits, so a missed finding still fails.
	const attack1Detail = g?.detail ?? "";
	check("ATTACK 1 message names the true tags and no foreign sha", /v6\.4\.0/.test(attack1Detail) && (() => {
		try {
			assertNoForeignSha(attack1Detail);
			return true;
		} catch {
			return false;
		}
	})());

	g = await gradePin(r, pin({ sha: "f".repeat(40), comment: "v6.4.0", claim: "6.4.0" }), floors);
	check("ATTACK 2 sha that resolves to nothing is caught", g?.code === "UNRESOLVABLE", g?.code);

	g = await gradePin(r, pin({ sha: "b".repeat(40), comment: "v4", claim: "4" }), floors);
	check("ATTACK 3 downgrade with an honest comment is caught", g?.code === "DOWNGRADE", g?.code);
	check("ATTACK 3 names the floor it fell below", /6\.4\.0/.test(g?.detail ?? ""));

	g = await gradePin(r, pin({ sha: "c".repeat(40), comment: "v6.4.0", claim: "6.4.0" }), floors);
	check("a real commit no tag names is caught", g?.code === "NAMED-BY-NO-REF", g?.code);

	g = await gradePin(r, pin({ action: "vendor/annotated", sha: "e".repeat(40), comment: "v3.36.2", claim: "3.36.2" }), floors);
	check("an annotated tag that peels grades on its peeled commit", g === null, g?.code);

	g = await gradePin(r, pin({ action: "vendor/annotated", sha: "d".repeat(40), comment: "v3.36.2", claim: "3.36.2" }), floors);
	check("a pin ON the tag object is diagnosed, not crashed", g?.code === "PIN-IS-TAG-OBJECT", g?.code);
	check("the tag-object message may print its own peel", /e{40}/.test(g?.detail ?? ""));

	g = await gradePin(r, pin({ sha: "a".repeat(40), comment: null, claim: null }), floors);
	check("a pin with no comment is caught", g?.code === "NO-COMMENT", g?.code);
	g = await gradePin(r, pin({ sha: "a".repeat(40), comment: "pinned", claim: null }), floors);
	check("a comment naming no release is caught", g?.code === "NO-VERSION-IN-COMMENT", g?.code);
	g = await gradePin(r, pin({ action: "who/knows", sha: "a".repeat(40), comment: "v1", claim: "1" }), {});
	check("an action with no recorded floor is caught", g?.code === "UNRESOLVABLE" || g?.code === "NO-FLOOR", g?.code);

	// Recorded pinning exceptions, both ways.
	const slsa = [{ file: "release.yml", line: 178, code: "slsa-framework/slsa-github-generator/.github/workflows/x.yml@v2.1.0", why: "tag" }];
	const excused = applyUnpinnedExceptions(slsa, { "slsa-framework/slsa-github-generator": "slsa-verifier refuses a sha-pinned generator ref" });
	check("a recorded pinning exception excuses its own case", excused.reported.length === 0 && excused.dead.length === 0);
	check("an unrecorded unpinned use is still reported", applyUnpinnedExceptions(slsa, {}).reported.length === 1);
	check("a dead pinning exception is a finding", applyUnpinnedExceptions([], { "who/knows": "stale" }).dead.length === 1);

	// The egress filter itself.
	let threw = false;
	try {
		assertNoForeignSha(`use ${"9".repeat(40)} instead`, new Set());
	} catch {
		threw = true;
	}
	check("the sha egress filter rejects a foreign sha", threw);
	check("the egress filter passes an allowed sha", (() => {
		try {
			assertNoForeignSha(`pin ${"a".repeat(40)}`, new Set(["a".repeat(40)]));
			return true;
		} catch {
			return false;
		}
	})());

	// There is no version-to-sha resolver whose output can be printed: prove it structurally.
	const src = readFileSync(fileURLToPath(import.meta.url), "utf8");
	const emitsRefSha = /emit\([^)]*ref\.sha/.test(src) || /detail:[^;]*ref\.sha/.test(src);
	check("no message is built from a comment-derived sha", emitsRefSha === false);

	// Anti-vacuity: an empty tree must fail, not pass.
	const empty = extractPins(join(HERE, "..", "node_modules", ".does-not-exist"));
	check("an absent .github yields zero pins", empty.pins.length === 0);

	// CI wiring self-check, both ways.
	const good = "jobs:\n  quality:\n    steps:\n      - run: npm run lint:action-pins\n  ci-success:\n    needs: [quality]\n";
	check("wiring check passes when the job is unconditional and required", checkCiWiring(good, "npm run lint:action-pins").length === 0);
	const skippable = "jobs:\n  quality:\n    if: false\n    steps:\n      - run: npm run lint:action-pins\n  ci-success:\n    needs: [quality]\n";
	check("wiring check fails a job that carries an if:", checkCiWiring(skippable, "npm run lint:action-pins").length > 0);
	const unrequired = "jobs:\n  quality:\n    steps:\n      - run: npm run lint:action-pins\n  ci-success:\n    needs: [other]\n";
	check("wiring check fails a job ci-success does not need", checkCiWiring(unrequired, "npm run lint:action-pins").length > 0);
	const absent = "jobs:\n  quality:\n    steps:\n      - run: npm test\n  ci-success:\n    needs: [quality]\n";
	check("wiring check fails when nothing runs the gate", checkCiWiring(absent, "npm run lint:action-pins").length > 0);

	// An `if:` that broadens is not an `if:` that skips, and treating it as one would push authors to the
	// plain form where an earlier red hides the gate.
	// biome-ignore lint/suspicious/noTemplateCurlyInString: a GitHub Actions expression is spelled with the same braces as a JS template placeholder, and the fixture has to carry it verbatim or it stops testing the string the workflow files actually contain.
	const broadened = "jobs:\n  quality:\n    steps:\n      - name: pins\n        if: ${{ !cancelled() }}\n        run: npm run lint:action-pins\n  ci-success:\n    needs: [quality]\n";
	check("wiring check accepts a step if: that only broadens", checkCiWiring(broadened, "npm run lint:action-pins").length === 0);
	// biome-ignore lint/suspicious/noTemplateCurlyInString: as above, a verbatim GitHub Actions expression.
	const narrowed = "jobs:\n  quality:\n    steps:\n      - name: pins\n        if: ${{ always() && github.event_name == 'push' }}\n        run: npm run lint:action-pins\n  ci-success:\n    needs: [quality]\n";
	check("wiring check still fails an if: that merely contains always()", checkCiWiring(narrowed, "npm run lint:action-pins").length > 0);
	check(
		"only always() and !cancelled() are broadening",
		// biome-ignore lint/suspicious/noTemplateCurlyInString: as above, a verbatim GitHub Actions expression.
		ifConditionIsBroadening("${{ !cancelled() }}") &&
			ifConditionIsBroadening("always()") &&
			!ifConditionIsBroadening("success()") &&
			!ifConditionIsBroadening("cancelled()") &&
			!ifConditionIsBroadening("false"),
	);

	// The failure that started this: the repair must be named in the direction that is safe, because the
	// message IS the fix instruction and the wrong direction downgrades a signer while reading as a tidy-up.
	const disagree = await gradePin(r, pin({ sha: "a".repeat(40), comment: "v4", claim: "4" }), floors);
	check(
		"the disagreement message says to move the comment and leave the sha",
		/MOVE THE COMMENT/.test(disagree?.detail ?? "") && /LEAVE THE SHA WHERE IT IS/.test(disagree?.detail ?? ""),
	);
	check("the disagreement message gives the cosign case as the reason", /cosign-installer/.test(disagree?.detail ?? ""));

	// THE REJECTION ARM, DRIVEN AS A PROCESS. This cannot be checked in-process: verdictReached and
	// verdictSkipped are module state in the guard, so calling either here would disarm the guard for the
	// remainder of this very self-test and every case after it would run unguarded. So the real file is
	// copied into a temporary tree beside a real copy of the guard, given a manifest that is deliberately
	// not JSON, and RUN. It throws where main() parses the manifest, which is the one route to the
	// rejection arm that needs no network and no token.
	//
	// THE ASSERTIONS ARE IN BOTH DIRECTIONS ON PURPOSE. Checking only that the guard stayed quiet would
	// pass just as well against a file that had stopped failing at all, so the exit status is pinned at 2
	// in the same breath: not 1, which would call a could-not-check a finding, and not 0.
	{
		const bed = mkdtempSync(join(tmpdir(), "action-pin-reject-"));
		try {
			mkdirSync(join(bed, "scripts", "lib"), { recursive: true });
			copyFileSync(join(HERE, "action-pin-comment-gate.mjs"), join(bed, "scripts", "action-pin-comment-gate.mjs"));
			copyFileSync(join(HERE, "lib", "verdict-guard.mjs"), join(bed, "scripts", "lib", "verdict-guard.mjs"));
			writeFileSync(join(bed, "scripts", "action-pin-manifest.json"), '{ "invocation": [ }');
			const run = spawnSync(process.execPath, [join(bed, "scripts", "action-pin-comment-gate.mjs")], { encoding: "utf8" });
			const both = `${run.stdout ?? ""}${run.stderr ?? ""}`;
			check("a crash still exits 2, the could-not-check status", run.status === 2, `status ${run.status}`);
			check("a crash still says what threw", /SyntaxError/.test(both));
			check("a crash declares its verdict as a skip", both.includes("VERDICT SKIPPED"), both.slice(0, 160).replace(/\n/g, " "));
			check(
				"the completion guard does NOT fire on top of a crash",
				!both.includes("without declaring a verdict"),
				both.slice(0, 160).replace(/\n/g, " "),
			);
		} finally {
			// No exit and no return inside the try, so this always runs. A `finally` skipped by a
			// process.exit in the block above is its own defect class and it has bitten this workspace.
			rmSync(bed, { recursive: true, force: true });
		}
	}

	const failed = cases.filter((c) => !c.ok);
	// PHRASED SO IT CANNOT BE SKIM-READ AS THE OPPOSITE OF THE VERDICT. It used to print
	// "<n>/<total> passed" on every run, failing ones included, so a reader scanning a red log met a
	// summary line whose last word was "passed" above the failure it was reporting. That is the same
	// defect scripts/coverage-gate.sh carried, where a narrow-margin advisory opened with the word
	// "passing" one line above FAILED. A failing run leads with the failure count here.
	console.log(
		failed.length === 0
			? `\n[action-pin] self-test: all ${cases.length} case(s) passed`
			: `\n[action-pin] self-test: ${failed.length} of ${cases.length} case(s) FAILED`,
	);
	if (cases.length < 34) {
		console.error("[action-pin] FAIL: the self-test has fewer cases than it is meant to; it is no longer proving the classes.");
		verdictReached(1, cases.length);
		return 1;
	}
	verdictReached(failed.length, cases.length);
	return failed.length === 0 ? 0 : 1;
}

// ---------------------------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------------------------

/**
 * Sibling-repo report. NEVER gating: this repo cannot fail on a file it does not own, and a gate that
 * red-lights on someone else's tree is a gate people delete. It exists so the findings can be routed
 * as patches, and it grades with exactly the same code, including the sha egress filter.
 */
async function workspaceReport(manifest) {
	const workspaceRoot = resolve(ROOT, "..");
	const tok = token();
	if (!tok) {
		console.error("[action-pin] workspace report needs a token; skipping resolution and printing the census only.");
	}
	const resolver = tok ? makeLiveResolver(tok) : null;
	for (const entry of readdirSync(workspaceRoot).sort()) {
		if (entry.startsWith(".")) continue; // sibling lanes' worktrees are not repos of their own
		const repo = join(workspaceRoot, entry);
		if (!existsSync(join(repo, ".github", "workflows"))) continue;
		const { pins, unpinned } = extractPins(repo);
		let findings = 0;
		for (const u of unpinned) {
			console.log(`[workspace] ${entry}/${u.file}:${u.line} UNPINNED (${u.why})`);
			findings += 1;
		}
		if (resolver) {
			for (const pin of pins) {
				let g = null;
				try {
					g = await gradePin(resolver, pin, manifest.floor, { skipFloor: true });
				} catch (e) {
					g = { code: "UNREACHABLE", detail: e instanceof Error ? e.message : String(e) };
				}
				if (g) {
					out.length = 0;
					emit(`[workspace] ${entry}/${pin.file}:${pin.line} [${g.code}] ${g.detail}`);
					flush("out");
					findings += 1;
				}
			}
		}
		console.log(`[workspace] ${entry}: ${pins.length} pins, ${findings} finding${findings === 1 ? "" : "s"}`);
	}
	verdictSkipped("workspace report: sibling repositories are reported, never gated, so this run decides nothing here");
	return 0;
}

async function main() {
	if (SELF_TEST) return selfTest();

	if (!existsSync(MANIFEST_PATH)) {
		console.error(`[action-pin] FAIL: ${MANIFEST_PATH} is missing, so reach and the downgrade floors are unrecorded.`);
		verdictSkipped("the manifest is missing, so reach and the downgrade floors are unrecorded", { require: true });
		return 2;
	}
	const manifest = JSON.parse(readFileSync(MANIFEST_PATH, "utf8"));
	if (WORKSPACE) return workspaceReport(manifest);

	const { pins, unpinned, local, filesWithUses } = extractPins(ROOT);

	if (CENSUS) {
		for (const p of pins) console.log(`${p.file}:${p.line}\t${p.action}${p.subpath}\t${p.sha}\t${p.comment ?? "<none>"}`);
		console.log(`\n${pins.length} pins, ${unpinned.length} unpinned, ${local.length} local`);
		verdictReached(0, pins.length);
		return 0;
	}

	let failures = 0;
	const fail = (line) => {
		failures += 1;
		emit(`[action-pin] FAIL ${line}`);
	};

	// ANTI-VACUITY 1: nothing to check is a failure. The exit code below is derived from the finding
	// count alone, so an empty census would otherwise report a clean estate and exit 0.
	if (filesWithUses.size === 0) {
		emit(`[action-pin] FAIL: no workflow file under ${join(ROOT, ".github")} contains a live \`uses:\`. A pass here would prove nothing.`);
		flush();
		verdictSkipped("no workflow file carries a live `uses:`, so there was nothing to grade", { require: true });
		return 2;
	}
	if (pins.length === 0) {
		emit("[action-pin] FAIL: workflow files contain `uses:` lines but not one parsed as a pin. The extractor or the pinning convention has moved.");
		flush();
		verdictSkipped("uses: lines are present and none parsed as a pin, so the extractor or the convention has moved", { require: true });
		return 2;
	}

	// ANTI-VACUITY 2: reach is measured against a recorded floor, per file and in total.
	if (pins.length < manifest.reach.minPins) {
		fail(`reach shrank: ${pins.length} pins found, manifest floor is ${manifest.reach.minPins}. Pins were removed or the extractor stopped matching them.`);
	}
	if (filesWithUses.size < manifest.reach.minFilesWithUses) {
		fail(`reach shrank: ${filesWithUses.size} workflow files carry a live \`uses:\`, manifest floor is ${manifest.reach.minFilesWithUses}.`);
	}
	// ANTI-VACUITY 3: a file whose `uses:` lines all failed to parse is an extractor break, not a clean file.
	for (const [file, counts] of filesWithUses) {
		if (counts.parsed === 0) fail(`${file} has ${counts.liveUses} live \`uses:\` lines and none parsed. The extractor is not reading this file.`);
	}

	// Recorded pinning exceptions. One real case exists in the estate: the SLSA generator must be pinned
	// by TAG, because slsa-verifier refuses provenance minted from a sha-pinned generator ref. An
	// exception is a decision on the record, keyed by action rather than by line so it survives edits,
	// and a DEAD exception fails too: an exemption that matches nothing is another comment that lies.
	const { reported, dead } = applyUnpinnedExceptions(unpinned, manifest.unpinnedException ?? {});
	for (const u of reported) fail(`${u.file}:${u.line} \`uses:\` is not pinned to a commit sha (${u.why}).`);
	for (const k of dead) fail(`scripts/action-pin-manifest.json records a pinning exception for ${k}, and nothing in this repo matches it.`);

	// ANTI-VACUITY 4: the gate must be wired where it cannot be skipped from, and it checks that itself.
	const ciPath = join(ROOT, ".github", "workflows", "ci.yml");
	if (!existsSync(ciPath)) fail("no .github/workflows/ci.yml, so the gate cannot show where it runs.");
	else for (const p of checkCiWiring(readFileSync(ciPath, "utf8"), manifest.invocation)) fail(`CI wiring: ${p}`);

	const tok = token();
	if (!tok) {
		emit("[action-pin] FAIL: no GITHUB_TOKEN or GH_TOKEN. The gate resolves pins against the GitHub ref graph and will not");
		emit("[action-pin]       pass on an unresolved tree. Export a token, or run --self-test for the offline classes.");
		flush();
		verdictSkipped("no GITHUB_TOKEN or GH_TOKEN, so no pin could be resolved", { require: true });
		return 2;
	}
	const resolver = makeLiveResolver(tok);

	for (const pin of pins) {
		let g;
		try {
			g = await gradePin(resolver, pin, manifest.floor);
		} catch (e) {
			if (/** @type {{ unreachable?: unknown }} */ (e)?.unreachable) {
				emit(`[action-pin] FAIL: could not resolve ${pin.file}:${pin.line}: ${e instanceof Error ? e.message : String(e)}`);
				emit("[action-pin]       An unresolvable pin is a failure, not a skip.");
				flush();
				verdictSkipped("the GitHub ref graph could not be reached, so the pins are ungraded", { require: true });
				return 2;
			}
			throw e;
		}
		if (g) fail(`${pin.file}:${pin.line} [${g.code}] ${g.detail}`);
	}

	flush();
	const actions = new Set(pins.map((p) => p.action));
	const summary =
		`[action-pin] ${pins.length} pins across ${filesWithUses.size} workflow files, ${actions.size} distinct actions, ` +
		`${failures} finding${failures === 1 ? "" : "s"}.`;
	console.log(summary);
	verdictReached(failures, pins.length);
	return failures === 0 ? 0 : 1;
}

main().then(
	// Every `return` in main() declares first, so the fulfilled arm is already covered: the four
	// verdictSkipped returns at the manifest, the empty-uses, the unparsed-uses and the no-token arms,
	// the verdictSkipped inside the unreachable-ref catch, and the two verdictReached returns for the
	// census and the graded run. That is the whole of main's exit surface, checked rather than assumed.
	(code) => process.exit(code),
	(e) => {
		console.error(`[action-pin] FAIL: ${e?.stack ?? e}`);
		// A CRASH IS A REFUSAL AND HAS TO BE DECLARED LIKE ONE. Without the line below this arm was the
		// one path out of this file that reached the process exit having declared nothing, and the
		// completion guard then fired ON TOP OF a perfectly good failure. Driven, not argued: making the
		// unguarded JSON.parse of the manifest throw produced exit 2, the SyntaxError and its stack on
		// stderr, and then the guard adding that "the verdict was never reached, so nothing in this run
		// was capable of failing" and that "it wrote nothing at all to stdout, so it did no work". The
		// first two are false, the third is misleading, and main() had simply thrown part of the way
		// through, which is exactly a could-not-check. The cost is not cosmetic: a guard that contradicts
		// a real finding sends the next reader off to disprove a red that was already true.
		//
		// THE EXIT CODE DOES NOT MOVE, and that is the point. 2 was already the right status and stays 2:
		// `require` makes the skip a failure and sets process.exitCode = 1, the explicit process.exit(2)
		// below carries the 2 regardless, and the guard re-applies a refusal only on a code of 0. Nothing
		// here was wrong except that the refusal was never stated.
		verdictSkipped(`the gate threw before reaching a verdict: ${e instanceof Error ? e.message : String(e)}`, { require: true });
		process.exit(2);
	},
);
