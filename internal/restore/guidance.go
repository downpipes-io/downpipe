package restore

import (
	"fmt"
	"strings"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// The reserved cf-config metadata record names. They match the engine's CF_CONFIG_IDENTITY_ID
// and CF_CONFIG_COVERAGE_ID (engine src/sources/cf-config-surfaces.ts). The leading underscore
// marks a reserved name that no registry surface uses.
const (
	cfConfigIdentityName = "_cf-config-identity"
	cfConfigCoverageName = "_cf-config-coverage"
)

// GuidanceFor returns the out-of-band re-provision/replay guidance for a record whose
// source type is restored by re-provisioning rather than a blind write (SPEC.md 12.1):
// `workers`, `cf-config`, `stream`, `images` and `artifacts` (the five types for which
// spec.ReprovisionSourceType returns true). It mirrors the engine's restore sink, which never blind-redeploys a Worker,
// blindly re-applies a Cloudflare-config surface, or re-uploads media from a backup
// (any of which could brick a live service or silently diverge from it); the offline
// reader still decrypts and hash-verifies the value and writes those verified bytes out
// for the operator, but it presents this guidance so the operator re-provisions
// deliberately and never mistakes the written bytes for a live re-apply. It is a pure
// function of the record, returns text only, and reaches nothing. For a source type that
// restores by a direct value write (kv, r2, secrets, d1) it returns "".
//
// The Worker text distinguishes the three record kinds the Workers source emits (the
// script content, the settings, and the versions inventory) by the engine's name suffix
// convention; a "/settings" record's secret VALUES were never captured (only a checklist
// of names/types), so the guidance never claims the backup holds them. The stream, images
// and artifacts records always include the inventory. When the downpipe had File contents
// on (the engine's includeContent), the same run also carries the files: each video's MP4
// and caption tracks, each image's bytes, and each repository's git objects (SPEC.md
// 12.1). One text per source type covers both cases, because a record name alone cannot
// say which option the downpipe had. So the text says the files are in the restore when
// File contents was on, and says to take them from the source of truth when it was off.
//
// Two cf-config record names are reserved by the engine for metadata, not surfaces:
// cfConfigIdentityName (which account and zone the backup is for) and cfConfigCoverageName
// (each registry surface the run has no record for, and why). The engine's restore preview
// lists both as informational (engine src/admin/restore-plan.ts, CF_CONFIG_COVERAGE_REASON).
// The offline reader gives them the same informational text, so it never tells an operator
// to replay a record that is not a surface.
func GuidanceFor(rec spec.ShardRecord) string {
	switch rec.SourceType {
	case spec.SourceWorkers:
		switch {
		case strings.HasSuffix(rec.Name, "/settings"):
			return "Workers script settings: re-create the bindings and secrets from the verified settings snapshot (secret values were never captured; the checklist lists their names and types to re-provision)."
		case strings.HasSuffix(rec.Name, "/versions"):
			return "Workers version inventory: informational only; re-deploy from the script content record."
		default:
			return "Workers script code: re-deploy the script from the verified content snapshot (wrangler deploy or the Workers API), then apply its settings record. The offline tool never blind-redeploys a Worker."
		}
	case spec.SourceCFConfig:
		switch rec.Name {
		case cfConfigIdentityName:
			return "Cloudflare configuration backup identity: informational only. It records which account and zone this backup is for. It is not a surface, so there is nothing to replay."
		case cfConfigCoverageName:
			return "Cloudflare configuration coverage: informational only. It names each surface this backup has no record for, and why: not used, not on the plan, no zone selected, or not selected. It is not a surface, so there is nothing to replay."
		}
		return "Cloudflare configuration surface: replay it from the verified snapshot through the Cloudflare API, or re-apply an idempotent surface in the console with an edit-scoped token. The offline tool never blindly re-applies a configuration surface."
	case spec.SourceStream:
		return "Cloudflare Stream: re-upload the video binaries, then replay each video's verified metadata (name, requireSignedURLs, allowed origins, user meta) through the Stream API. When File contents was on for the downpipe, the backup holds the files the run captured: each video's MP4 (<uid>/video.mp4) and its caption tracks (<uid>/captions/<lang>.vtt). A file the run could not capture, for example a video whose download was not enabled or not ready, is an incompleteness marker, and an applied restore lists each marker. When File contents was off, the backup holds only the metadata. For a file that the backup does not hold, upload the video from your source of truth. The offline tool never re-uploads a video from a backup."
	case spec.SourceImages:
		return "Cloudflare Images: re-upload the image binaries, then replay the verified per-image metadata and the account-level variant definitions through the Images API. When File contents was on for the downpipe, the backup holds the files the run captured: each image's bytes (<id>/blob). A file the run could not capture, for example an image larger than the size limit, is an incompleteness marker, and an applied restore lists each marker. When File contents was off, the backup holds only the metadata. For a file that the backup does not hold, upload the image from your source of truth. The offline tool never re-uploads an image from a backup."
	case spec.SourceArtifacts:
		return "Cloudflare Artifact Registry: re-create each repository from its verified metadata, then re-push its contents through the registry's git smart-HTTP endpoint. When File contents was on for the downpipe, the backup holds the git objects the run captured, for the full history: the log (<ns>/<repo>/log), each commit and tree, and each file blob (<ns>/<repo>/blob/<hash>). Contents the run could not capture, for example a namespace whose repository list it could not read, are an incompleteness marker, and an applied restore lists each marker. When File contents was off, the backup holds only the metadata. For contents that the backup does not hold, push them from your source of truth. The offline tool never re-pushes to a registry from a backup."
	default:
		return ""
	}
}

// D1ReplayGuidance returns the exact two-command turnkey for applying a d1 record's
// verified dump to a fresh database offline. A d1 record is a direct value write, NOT a
// reprovision type (GuidanceFor returns "" for it and ReprovisionSourceType is false), so
// this guidance is separate: the offline reader writes the verified SQLite-compatible dump
// to a .sql file (see d1OutputKey) and the operator applies it deliberately to a NEW
// database, never blindly over a live one. It is a constant string and reaches nothing.
//
// The two commands are: build a local SQLite database from the dump, then load that
// database into D1. The reader emits one .sql per d1 record in lexicographic replay order
// (header, then row pages, then schema), so the operator applies the files for one
// database in name order.
func D1ReplayGuidance() string {
	return "D1 database dump: apply the verified .sql file(s) to a NEW database in name order, then load it into D1. For one database: sqlite3 restored.sqlite < <db>/00-header.sql (then each <db>/10-rows/* and <db>/20-schema.sql, or the single <db>.sql for a legacy whole-dump), then wrangler d1 execute <DB_NAME> --file=<file>.sql or import the built restored.sqlite. The offline tool never blind-applies a dump over a live database; apply to a fresh one and cut over deliberately."
}

// d1OutputKey gives a d1 record's destination key a .sql suffix on a file sink so the
// operator can apply the written dump turnkey (sqlite3 newdb.sqlite < <name>.sql). It is
// applied ONLY to d1 records on the file target; every other source type and every other
// target keep the unmodified key, so this never blind-rewrites another type's key. A key
// that already ends in .sql (defensive) is left unchanged so the suffix is never doubled.
//
// It is NOT applied when the record's D1 descriptor names a body format this release cannot
// render (unrenderable is that label, from d1UnrenderableLabel). Naming such a file .sql is a
// second, independent untruth on top of the silent success: the bytes are JSON, and it is the
// name that turns unhelpful output into harmful output, because the operator reaches for
// sqlite3 on the strength of the extension before reading anything else. Such a record keeps
// its bare name, which claims nothing about the contents.
//
// The descriptor is what decides this, and it has to be, because MakePlan resolves every
// destination key before a single byte is decrypted. That is also why the descriptor is worth
// carrying at all: it is the only thing that can answer this question at plan time. The
// verified body is checked as well once it is in hand, so a body that disagrees with its
// descriptor is still reported, but the key follows the descriptor.
func d1OutputKey(key, unrenderable string) string {
	if unrenderable != "" {
		return key
	}
	if strings.HasSuffix(key, ".sql") {
		return key
	}
	return key + ".sql"
}

// D1UnrenderableGuidance returns the operator guidance for d1 records this release cannot
// render, given how many there are and whether this run is writing. It is printed alongside
// D1ReplayGuidance rather than instead of it, because one restore can carry both kinds, and it
// says plainly that the sqlite3 step does not apply to these files.
//
// apply carries the tense, and it is a parameter rather than a fixed wording because the plan
// report prints on a dry run too. A dry run writes nothing, and a sentence saying bytes "were
// written" on a run that wrote none would be exactly the kind of imprecision this whole change
// exists to remove.
//
// It never tells the operator to discard anything. The bytes are verified and complete, and a
// downpipe release that knows the label reads them; this text exists so the operator learns
// that from the tool rather than from sqlite3 refusing to parse the file.
func D1UnrenderableGuidance(n int, apply bool) string {
	written := "will be written unchanged"
	if apply {
		written = "were written unchanged"
	}
	return fmt.Sprintf("%d D1 record(s) carry a body format this release cannot render. "+
		"Their verified bytes %s and are NOT SQL, so the sqlite3 and wrangler steps above do "+
		"not apply to them and a database with such a record cannot be rebuilt in full from "+
		"this restore. Each one is named below with the format label it carries; use a "+
		"downpipe release that reads that label. Nothing here is corrupt, and the files are "+
		"worth keeping exactly as written.", n, written)
}
