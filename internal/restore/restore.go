package restore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"

	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// errStreamTeardown is the sentinel applyStream passes to pr.CloseWithError to unblock the
// reader goroutine when the target's WriteStream returned before draining the pipe (the most
// reachable trigger is the O_EXCL no-clobber guard rejecting a key that appeared in the
// TOCTOU window between MakePlan and the write). Closing the read end makes the goroutine's
// blocked pw.Write fail so it finishes and signals done, instead of blocking forever. It is
// teardown noise, NOT an integrity verdict, so applyStream distinguishes it with errors.Is
// and never lets it mask the target's real failure reason. RestoreRecordTo may wrap the pipe
// write error (it tees plaintext through io.MultiWriter, so the closed-pipe error can surface
// wrapped as coded(ExitUnverified, ...)); errors.Is unwraps, so the match still holds.
var errStreamTeardown = errors.New("restore: stream bridge torn down after target returned early")

// recordReader is the read side of an opened, verified run that this package needs: the
// record list and the per-record reassemble-and-verify. *format.Reader satisfies it, so
// the package depends on the reader interface rather than the concrete type, which keeps
// the planner testable without standing up a whole archive.
type recordReader interface {
	Records() []spec.ShardRecord
	RestoreRecord(rec spec.ShardRecord) ([]byte, error)
}

// streamingReader is an optional capability a recordReader may add: restore a streamable
// record's value straight to an io.Writer (decrypting one chunk at a time) and report
// whether a given record is streamable. *format.Reader satisfies it. Apply uses it only
// when both the reader and the target opt in and the record is streamable, so a value
// larger than memory restores in bounded memory; otherwise the existing buffering path
// (RestoreRecord + Write) is unchanged. It is a separate interface so a reader (or a test
// fakeReader) that does not implement it keeps the whole-value path with no change.
type streamingReader interface {
	IsStreamable(rec spec.ShardRecord) bool
	RestoreRecordTo(rec spec.ShardRecord, dst io.Writer) error
}

// streamThreshold is the smallest record (by signed manifest plaintextSize) restored
// through the per-record streaming path. Streaming a record costs an O_EXCL placeholder,
// a temp file and a rename on the file sink where the buffered path is one open-write,
// so below this size the buffered path is strictly better; at or above it, bounding
// memory matters more than the extra syscalls. The value is a trade, not a correctness
// bound: both paths apply the same plaintext SHA-384 and no-clobber gates.
const streamThreshold = 8 << 20

// ConflictKind classifies why a record cannot be written without clobbering.
type ConflictKind string

const (
	// ConflictExisting is a record whose destination key already exists in the target,
	// so writing would overwrite state the operator already has.
	ConflictExisting ConflictKind = "existing"
	// ConflictCollision is a record whose destination key another record in this run
	// also maps to, so writing both would have the second clobber the first.
	ConflictCollision ConflictKind = "collision"
	// ConflictUnrepresentable is a record whose name the target cannot represent as a
	// destination key (for example a name that is not a valid environment-variable
	// name), so the record is reported rather than silently dropped or mangled.
	ConflictUnrepresentable ConflictKind = "unrepresentable"
)

// PlannedWrite is one record the plan would write: its name, the destination key in the
// target, and the byte length from the signed manifest. It carries no value and no key
// material.
type PlannedWrite struct {
	Name  string
	Key   string
	Bytes int64
}

// Conflict is one record the plan refuses to write because doing so would clobber, and
// the reason. It carries the record name and the destination key (or the offending name
// for an unrepresentable record), never a value. Detail is a short human reason.
type Conflict struct {
	Name   string
	Key    string
	Kind   ConflictKind
	Detail string
}

// Reprovision is one record whose source type restores by re-provisioning or replay
// rather than a blind write (SPEC.md 12.1): the spec.ReprovisionSourceType set (`workers`,
// `cf-config`, `stream`, `images`, `artifacts`). The offline reader decrypts and hash-verifies the
// value the same as any other record (so the snapshot's recoverability is proven), and on
// a file sink it writes the verified bytes out for the operator, but it never treats the
// write as a live re-apply. This note carries the
// record name, the destination key the verified bytes were (or would be) written to for a
// value sink, and the operator guidance text; it carries no value. It exists so an
// operator sees exactly which records need deliberate re-provisioning.
type Reprovision struct {
	Name       string
	Key        string
	SourceType string
	Guidance   string
}

// D1Unrenderable is one planned d1 record whose descriptor names a downpipe D1 body format
// this release cannot render: its name, the destination key it will be written to (bare, with
// no .sql suffix), and the format label itself. The label is carried so the operator is told
// which release they need rather than only that they need another one.
type D1Unrenderable struct {
	Name   string
	Key    string
	Format string
}

// Plan is the outcome of diffing a run against a target without writing anything: the
// records that would be written, the records that conflict, and the totals. It is the
// dry-run result, and it is what an apply consumes. Everything in it is counts, names,
// keys, sizes and enums; nothing in it is a value or key material.
type Plan struct {
	// Kind is the target enum (file, env) the plan was computed against.
	Kind string
	// Writes are the records that would be written, in canonical record order.
	Writes []PlannedWrite
	// Conflicts are the records the plan refuses to write, in canonical record order.
	Conflicts []Conflict
	// Reprovision lists the records whose source type restores by re-provisioning or
	// replay rather than a blind write (the spec.ReprovisionSourceType set: `workers`,
	// `cf-config`, `stream`, `images`, `artifacts`), in canonical record order. A reprovision record is
	// still planned (it is verified, and on a value sink
	// its bytes are written for the operator), so it also appears in Writes; this slice
	// surfaces the out-of-band guidance alongside it.
	Reprovision []Reprovision
	// HasD1File is true when the plan would write at least one d1 record to a file sink as
	// a .sql dump (d1OutputKey). It lets the caller surface the D1ReplayGuidance apply
	// commands once, alongside the planned writes; d1 is a direct value write, not a
	// reprovision type, so this is separate from Reprovision.
	//
	// A d1 record whose descriptor names a format this release cannot render does NOT set
	// it. That record is not planned to a .sql key and the sqlite3 guidance is not about it,
	// so a run carrying only such records prints no replay guidance at all rather than
	// guidance the operator cannot follow.
	HasD1File bool
	// D1Unrenderable lists the d1 records whose D1 DESCRIPTOR names a body format this
	// release cannot render, in canonical record order. Such a record is still planned and
	// still written (its bytes are verified and are the operator's only copy), so it also
	// appears in Writes, at a key with no .sql suffix; this slice is what lets a caller say
	// which records those are and which label each carries, in a dry run as well as an
	// apply.
	//
	// It is descriptor-derived because a plan decrypts nothing. The verified body is checked
	// separately once it is in hand, and that lands in Result.Unrenderable, so a body whose
	// label disagrees with its descriptor is still surfaced.
	D1Unrenderable []D1Unrenderable
	// WriteCount is the number of planned (non-conflicting) writes. The load-all MakePlan
	// fills Writes and sets WriteCount = len(Writes); the streaming ApplyStreaming sets
	// WriteCount without materialising the per-record Writes slice (which is O(records)),
	// so a caller reports the planned-write count through WriteCount on either path.
	WriteCount int
	// TotalRecords is the run's verified record count (writes plus conflicts).
	TotalRecords int
	// TotalBytes is the sum of the manifest plaintext sizes of the writable records.
	TotalBytes int64
}

// HasConflicts reports whether any record cannot be written without clobbering.
func (p *Plan) HasConflicts() bool { return len(p.Conflicts) > 0 }

// MakePlan diffs the opened run against the target and returns the no-clobber plan
// without writing or decrypting anything. A record is a conflict when the target cannot
// represent its name, when its destination key already exists in the target, or when
// two records collide on one destination key; every other record is a planned write
// with its manifest byte size. Records are processed in the reader's canonical order so
// a collision is reported against the later record and the earlier one still plans to
// write.
func MakePlan(r recordReader, t Target) (*Plan, error) {
	existing, err := t.Existing()
	if err != nil {
		return nil, fmt.Errorf("enumerate target state: %w", err)
	}
	plan := &Plan{Kind: t.Kind()}
	// claimed tracks destination keys this plan would write, so a second record that
	// maps to the same key is a collision rather than a silent overwrite within the run.
	claimed := make(map[string]struct{})
	for _, rec := range r.Records() {
		plan.TotalRecords++
		key, conflict := classifyRecord(t, rec, existing, claimed)
		if conflict != nil {
			plan.Conflicts = append(plan.Conflicts, *conflict)
			continue
		}
		claimed[key] = struct{}{}
		plan.Writes = append(plan.Writes, PlannedWrite{
			Name: rec.Name, Key: key, Bytes: rec.PlaintextSize,
		})
		plan.WriteCount++
		plan.TotalBytes += rec.PlaintextSize
		annotateD1(plan, t, rec, key)
		annotateReprovision(plan, rec, key)
	}
	return plan, nil
}

// annotateD1 records what the plan knows about one d1 record on a file sink: either it is
// planned as a .sql dump (HasD1File, so the caller prints the replay guidance once), or its
// descriptor names a body format this release cannot render, in which case it is listed with
// that label and HasD1File is deliberately NOT set for it.
//
// The two are exclusive by construction, because both read the same descriptor answer that
// classifyRecord used to decide the key. That is the point: the guidance and the file name
// cannot disagree about whether a record is SQL, because one function decides both.
func annotateD1(plan *Plan, t Target, rec spec.ShardRecord, key string) {
	if rec.SourceType != spec.SourceD1 || t.Kind() != "file" {
		return
	}
	if label := d1DescriptorUnrenderable(rec); label != "" {
		plan.D1Unrenderable = append(plan.D1Unrenderable, D1Unrenderable{Name: rec.Name, Key: key, Format: label})
		return
	}
	plan.HasD1File = true
}

// classifyRecord resolves the destination key for one record against the target, applying
// the env-unrepresentable, d1 key-rewrite, existing-key and within-run collision rules. It
// returns the resolved key and a nil conflict when the record may be written, or a non-nil
// conflict (and an empty key) when the record must be skipped.
func classifyRecord(t Target, rec spec.ShardRecord, existing, claimed map[string]struct{}) (string, *Conflict) {
	// A reprovision source type (`workers`, `cf-config`, `stream`, `images`, `artifacts`) is restored
	// by re-provisioning or replay, never a blind write (SPEC.md 12.1). The env sink
	// cannot represent such a record as a dotenv value without mis-restoring it (a Worker
	// bundle, a config surface or a media inventory is not an environment variable), so
	// refuse it there rather than emit it silently. A value sink (file) writes the
	// verified bytes out for the operator and a
	// discard sink verifies it and writes nothing, so both proceed to the normal write
	// path below; the reprovision note is attached once a destination key is resolved.
	if spec.ReprovisionSourceType(rec.SourceType) && t.Kind() == "env" {
		return "", &Conflict{
			Name: rec.Name, Kind: ConflictUnrepresentable,
			Detail: GuidanceFor(rec) + " It cannot be written to an env target; use the file sink and re-provision from the bytes.",
		}
	}
	key, kerr := t.Key(rec.Name)
	if kerr != nil {
		return "", &Conflict{
			Name: rec.Name, Kind: ConflictUnrepresentable, Detail: kerr.Error(),
		}
	}
	// A d1 record's body is a SQLite-compatible dump (SPEC.md 12.1). On the file sink
	// give it a .sql suffix so the operator can apply it turnkey (sqlite3 newdb.sqlite
	// < <name>.sql, then wrangler d1 execute). The suffix is added ONLY for d1 on the
	// file target, so no other source type's key is rewritten; the collision and
	// existing-key checks below run against the suffixed key so the plan stays
	// consistent with the bytes that get written.
	//
	// The one d1 record that does NOT get the suffix is one whose descriptor names a body
	// format this release cannot render: see d1OutputKey for why the name matters as much
	// as the report does.
	if rec.SourceType == spec.SourceD1 && t.Kind() == "file" {
		key = d1OutputKey(key, d1DescriptorUnrenderable(rec))
	}
	if _, taken := existing[key]; taken {
		return "", &Conflict{
			Name: rec.Name, Key: key, Kind: ConflictExisting,
			Detail: "the destination key already exists in the target",
		}
	}
	if _, taken := claimed[key]; taken {
		return "", &Conflict{
			Name: rec.Name, Key: key, Kind: ConflictCollision,
			Detail: "another record in this run maps to the same destination key",
		}
	}
	return key, nil
}

// annotateReprovision attaches an out-of-band reprovision note when a reprovision record
// (workers/cf-config/stream/images/artifacts) reached the write path (a file or discard
// sink), so the operator re-provisions deliberately and never mistakes the written bytes
// for a live re-apply.
func annotateReprovision(plan *Plan, rec spec.ShardRecord, key string) {
	if !spec.ReprovisionSourceType(rec.SourceType) {
		return
	}
	plan.Reprovision = append(plan.Reprovision, Reprovision{
		Name: rec.Name, Key: key, SourceType: rec.SourceType, Guidance: GuidanceFor(rec),
	})
}

// applyStream restores one streamable record through the streaming path: it bridges the
// reader's writer-shaped RestoreRecordTo to the target's reader-shaped WriteStream with an
// io.Pipe, so the decrypted plaintext flows chunk by chunk from the reader into the target
// without either side buffering the whole value. It returns the number of plaintext bytes
// written and up to markerPrefixLen captured leading bytes of the value, so the caller can run
// the incompleteness-marker shape check on a streamed value without buffering the whole of it.
//
// The reader writes into the pipe in a goroutine and closes the write end with the restore
// result. RestoreRecordTo checks the per-record plaintext SHA-384 only after the last byte
// has streamed, so on a tampered or truncated segment the bytes have already flowed before
// the error surfaces: CloseWithError propagates the reader's error to WriteStream's io.Copy,
// and the error is returned so the apply records the record as failed (the operator must not
// trust a file whose restore returned an error). The target's WriteStream stages the bytes in
// a temp file and only renames them into place on a clean copy, so a failed record leaves NO
// partial file at the destination (the buffering path's all-or-nothing guarantee).
//
// A target's WriteStream may return BEFORE it drains the pipe: the most reachable case is the
// O_EXCL no-clobber guard rejecting a key that appeared between MakePlan and the write. If the
// reader is still blocked in pw.Write with nobody reading pr, it would never finish and the
// receive on done would block forever (a permanent hang plus a leaked goroutine). To avoid
// that, the moment WriteStream returns the read end is closed with the errStreamTeardown
// sentinel, which makes the blocked pw.Write fail so the goroutine completes and signals done.
//
// Error precedence is then resolved so the induced teardown is never mistaken for a verdict:
// the reader's integrity verdict takes precedence (a tampered segment must read as a
// verification failure, not a downstream copy error), BUT only when it is a real verdict. When
// the reader's error is the teardown sentinel we induced (matched with errors.Is, which
// unwraps even if RestoreRecordTo wrapped it through io.MultiWriter), it is discarded and the
// target's real reason (for example the no-clobber rejection) is surfaced instead.
func applyStream(sr streamingReader, st StreamTarget, rec spec.ShardRecord, key string) (int64, []byte, error) {
	pr, pw := io.Pipe()
	// capture tees up to markerPrefixLen leading bytes for the marker shape check; counter counts
	// the total. Both read on this goroutine via WriteStream, so capture.prefix is fully populated
	// (up to the cap) once WriteStream has drained the pipe on the success path below.
	capture := &prefixReader{r: pr, limit: markerPrefixLen}
	counter := &countingReader{r: capture}
	type readResult struct{ err error }
	done := make(chan readResult, 1)
	go func() {
		rerr := sr.RestoreRecordTo(rec, pw)
		// Close the write end with the restore error so WriteStream's copy ends: a nil error
		// is a clean EOF, a non-nil error is delivered to the reader of the pipe.
		_ = pw.CloseWithError(rerr)
		done <- readResult{err: rerr}
	}()
	werr := st.WriteStream(key, counter, rec.PlaintextSize)
	// Unblock the reader goroutine before receiving on done: if WriteStream returned without
	// draining the pipe, the goroutine is parked in pw.Write and would never signal done.
	// Closing the read end with the sentinel makes that write fail so the goroutine finishes;
	// a defer here would fire too late because the receive below runs before the return.
	_ = pr.CloseWithError(errStreamTeardown)
	rr := <-done
	// The reader's integrity verdict takes precedence, unless it is the teardown error we just
	// induced (which is not a verdict): in that case fall through to the target's real reason.
	if rr.err != nil && !errors.Is(rr.err, errStreamTeardown) {
		return 0, nil, rr.err
	}
	if werr != nil {
		return 0, nil, werr
	}
	return counter.n, capture.prefix, nil
}

// countingReader forwards reads from r and counts the bytes, so the streaming apply can
// report the restored byte count without buffering the value.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// RecordFailure is one record that failed to restore during apply: its name, the
// destination key it would have occupied, and the failure reason. It carries no value.
type RecordFailure struct {
	Name   string
	Key    string
	Reason string
	// Err is the failure as an error rather than as text, so a caller can ask what CLASS
	// of failure it was (errors.Is against fs.ErrNotExist, errors.As for a coded exit)
	// instead of matching on Reason. The command layer needs that distinction to tell an
	// absent object apart from a hash or authenticated-decrypt failure, which land on the
	// same exit code but demand opposite responses from an operator. Not serialised
	// anywhere: Reason remains the printed and receipt-visible form, so no output changes.
	Err error
}

// AnyAbsentObject reports whether any failed record failed because an object was not there
// at all, rather than because it failed a check. The two share exit codes, so the command
// layer asks this before deciding whether to tell an operator that nothing was retrieved to
// check. It is a question about the CAUSE only and never about the verdict.
func (res *Result) AnyAbsentObject() bool {
	for _, f := range res.Failed {
		if errors.Is(f.Err, fs.ErrNotExist) {
			return true
		}
	}
	return false
}

// DanglingSegments counts the DISTINCT seg/ object paths that a manifest named and the
// bucket did not hold, over the records this run actually tried to read (SPEC.md 10.1).
//
// Distinct, because segments are content addressed and shared: two records carrying the
// same bytes name one segment object, so counting failed records would report two dangling
// references where the bucket is missing one object. The path comes off
// format.SegmentReadError, which only a FETCH failure carries, so a segment that was
// present and failed its AEAD tag or its hash is never counted here.
//
// It is meaningful only after a pass that read segments (a deep verify or an applied
// restore). A shallow verify never opens a seg/ object, so it must report the count as
// absent rather than as this function's zero, and cmd/downpipe does exactly that.
func (res *Result) DanglingSegments() int64 {
	seen := map[string]struct{}{}
	for _, f := range res.Failed {
		if object, ok := absentSegment(f.Err); ok {
			seen[object] = struct{}{}
		}
	}
	return int64(len(seen))
}

// absentSegment reports whether err is a record failure whose cause was a seg/ object the
// manifest named and the bucket did not hold, and returns that object path. Both halves are
// required: format.SegmentReadError is carried only by a FETCH failure, so a segment that
// was present and failed its AEAD tag or its hash never matches, and fs.ErrNotExist is what
// separates "not there" from a read that was answered and went wrong some other way.
//
// It is one function because DanglingSegments (the count in the signed receipt) and
// DanglingOnly (the verdict in the exit status and the printed line) are answers to the same
// question, and the whole defect being fixed here was those two surfaces disagreeing.
func absentSegment(err error) (string, bool) {
	if !errors.Is(err, fs.ErrNotExist) {
		return "", false
	}
	var sre *format.SegmentReadError
	if !errors.As(err, &sre) {
		return "", false
	}
	return sre.Object, true
}

// DanglingOnly reports whether this pass failed records and EVERY one of them failed because
// a seg/ object was absent from the archive, so nothing was retrieved for them and no
// authentication tag, signed hash or signature failed anywhere in the pass.
//
// It is the question the exit status and the printed completeness line ask, and it is
// deliberately narrower than AnyAbsentObject. "Any" is enough to justify an extra sentence
// of guidance, which is all the command layer used it for. It is NOT enough to change a
// verdict: a pass holding one absent segment and one failed authentication tag has a real
// integrity finding in it, and that finding must take precedence, so this returns false and
// the harder code and the harder sentence stand.
//
// False on a pass with no failures at all: a clean pass is complete, not incomplete.
func (res *Result) DanglingOnly() bool {
	if len(res.Failed) == 0 {
		return false
	}
	for _, f := range res.Failed {
		if _, ok := absentSegment(f.Err); !ok {
			return false
		}
	}
	return true
}

// RecordReprovision is one reprovision-type record (workers, cf-config, stream, images,
// artifacts) that was decrypted and hash-verified during apply (so its recoverability is
// proven) but whose best-effort courtesy file-write could not be laid down as a plain file.
// The most common cause is a path collision on a file sink: a Worker's content record `<id>`
// occupies the file `<id>`, while its `<id>/settings` and `<id>/versions` siblings need
// `<id>` to be a directory, and a filesystem cannot hold `<id>` as both. These records are
// NOT failures: a reprovision record restores by deliberate re-provisioning from the surfaced
// guidance, never a blind file write, so the snapshot is fully recoverable and the operator
// re-provisions from the guidance. A reprovision record whose VERIFY (decrypt or plaintext
// hash) failed is a genuine integrity failure recorded in Failed, never here, so a corrupted
// reprovision record is never laundered as expected. The struct carries the record name, the
// destination key the verified bytes would have occupied, the source type, the operator
// guidance and the plain reason the courtesy write did not complete; it carries no value.
type RecordReprovision struct {
	Name       string
	Key        string
	SourceType string
	Guidance   string
	Reason     string
}

// Result is the honest outcome of an apply: how many records were written, which were
// verified-but-reprovision-only, which failed and why, and how many were skipped because the
// plan flagged them as conflicts. A per-record failure does not abort the apply; it is
// recorded here and the apply continues, so Restored, Reprovisioned and Failed together
// account for every planned write.
type Result struct {
	// Kind is the target enum the apply wrote to.
	Kind string
	// Restored is the number of records written and (for the value bytes) hash-verified.
	Restored int
	// BytesRestored is the sum of the restored records' value byte lengths.
	BytesRestored int64
	// Failed lists the records whose reassemble, verify or write failed.
	Failed []RecordFailure
	// ConflictKinds tallies SkippedConflicts by kind over the closed vocabulary, so the receipt can say
	// WHY records were refused without carrying a name. Counts only; nil when nothing was refused.
	ConflictKinds map[ConflictKind]int
	// Reprovisioned lists reprovision-type records that were decrypted and hash-verified
	// (recoverability proven) but whose best-effort courtesy file-write could not be laid down
	// as a plain file, most often a Worker content vs settings/versions path collision on a
	// file sink. These are reported distinctly and are NOT failures: the record restores by
	// deliberate re-provisioning, so it never makes OK() false. An integrity failure stays in
	// Failed, so a corrupted reprovision record is never laundered into this list.
	Reprovisioned []RecordReprovision
	// SkippedConflicts is the number of records the plan refused as clobbering and the
	// apply therefore did not attempt.
	SkippedConflicts int
	// DryRun is true when Apply was called without confirmation: the plan was computed
	// and reported but nothing was written.
	DryRun bool
	// IntegrityExit is the maximum normative per-record exit code (SPEC.md 8.5) observed
	// across the failed records: ExitPlaintext (4) for a plaintext-hash mismatch,
	// ExitUnverified (2) for a structural or AEAD failure. It is 0 when no failed record
	// carried a coded exit (an uncoded I/O failure such as a missing segment object), so the
	// caller falls back to a generic exit 1. It exists so a partial restore (and a discard
	// drill) propagates the true integrity class instead of flattening every per-record
	// failure to exit 1 (SPEC.md 8.5: a plaintext mismatch is exit 4, an AEAD/structural
	// failure exit 2).
	IntegrityExit int
	// IncompleteMarkers is the number of restored records that are INCOMPLETENESS MARKERS: the
	// source was only partially available when the run was written, so the record's value is a
	// sentinel placeholder (spec.ShardRecord.IncompleteMarker, or a value whose leading JSON key
	// is one of markerSentinelKeys), NOT the source's live data. It is a subset of Restored and
	// is NOT a failure: the value genuinely restored and hash-verified, so a marker never makes
	// OK() false. It exists so a caller can surface the records and exit a distinct advisory
	// instead of presenting a silent false-green (a `{"_skipped":…}` blob written as live data).
	IncompleteMarkers int
	// Markers lists the restored incompleteness-marker records (name, destination key, kind) for
	// the per-record warning. len(Markers) == IncompleteMarkers. It carries names, keys and the
	// kind only, never a value.
	Markers []RecordMarker
	// Unrenderable lists the restored d1 records whose verified body, or whose descriptor,
	// carries a downpipe D1 format label this release cannot render into SQL. It is a subset
	// of Restored and is NOT a failure: every byte was written unchanged and hash-verified,
	// so an unrenderable record never makes OK() false. It exists so the caller can name the
	// files, name the label each one needs, and exit format.ExitUnrenderable rather than
	// reporting a clean restore over a file the replay guidance would send to sqlite3.
	//
	// It is wider than Plan.D1Unrenderable, which a plan can only derive from the descriptor.
	// This is derived from the descriptor AND the decrypted body, so a record whose body
	// disagrees with its descriptor, or that carries no descriptor at all, appears here and
	// not there.
	Unrenderable []RecordUnrenderable
}

// recordConflicts copies the plan's refusals onto the result: the count, and the per-kind tally the
// receipt carries. Both apply paths (buffered and streaming) call it, so the two cannot disagree about
// the same plan, and the tally is derived from the plan's own conflicts rather than recounted, so the
// count and the tally cannot disagree either.
func recordConflicts(res *Result, plan *Plan) {
	res.SkippedConflicts = len(plan.Conflicts)
	if len(plan.Conflicts) == 0 {
		res.ConflictKinds = nil
		return
	}
	kinds := make(map[ConflictKind]int, 3)
	for _, c := range plan.Conflicts {
		kinds[c.Kind]++
	}
	res.ConflictKinds = kinds
}

// OK reports whether the apply finished with no per-record failure. A reprovision-only
// record (verified, but its courtesy file-write could not be laid down) is NOT a failure, so
// it does not make OK() false; only a real failure (a reassemble, verify or non-reprovision
// write failure) does. It is false on any failure, so a caller maps a partial restore to a
// non-zero result, while a restore whose only non-written records are reprovision-only by
// design stays OK and exits zero.
func (res *Result) OK() bool { return len(res.Failed) == 0 }

// markerSentinelKeys is the set of incompleteness-marker sentinel keys (SPEC.md 12.1): a record
// whose value is a JSON object whose leading key is one of these was written when the source was
// only partially available at backup time, so the value is a placeholder sentinel, not the
// source's live data. This set drives the SHAPE-CHECK fallback that catches such a marker in an
// archive sealed BEFORE the engine stamped the authoritative spec.ShardRecord.IncompleteMarker
// field; the stamped field, when present, is authoritative and false-positive-free.
var markerSentinelKeys = map[string]struct{}{
	"_unavailable": {},
	"_skipped":     {},
	"_pending":     {},
	"_truncated":   {},
	"_refused":     {},
}

// markerPrefixLen bounds how many leading value bytes the streaming apply captures for the
// shape check. The sentinel is the FIRST key of a JSON object, so a small prefix is always
// enough to read it while a larger-than-memory streamed value is never buffered: 512 bytes
// covers the opening brace plus whitespace plus the longest sentinel key with ample margin.
const markerPrefixLen = 512

// RecordMarker is one restored record identified as an incompleteness marker: its name, the
// destination key it was written to, and the marker kind (the sentinel key, or the value of the
// stamped spec.ShardRecord.IncompleteMarker field). It carries no value.
type RecordMarker struct {
	Name string
	Key  string
	Kind string
}

// RecordUnrenderable is one restored d1 record this release cannot render into SQL: its name,
// the destination key its verified bytes were written to, and the downpipe D1 format label
// that names what would read them. It carries no value.
type RecordUnrenderable struct {
	Name   string
	Key    string
	Format string
}

// noteUnrenderable records a just-written d1 record whose format label this release cannot
// render. It is called only after the write succeeded and Restored was incremented, so
// Unrenderable stays a subset of Restored, the same discipline noteMarker keeps.
func (res *Result) noteUnrenderable(rec spec.ShardRecord, key string, value []byte) {
	label := d1RecordUnrenderable(rec, value)
	if label == "" {
		return
	}
	res.Unrenderable = append(res.Unrenderable, RecordUnrenderable{Name: rec.Name, Key: key, Format: label})
}

// markerKind classifies a restored record as an incompleteness marker and returns its kind, or
// "" for a normal record. Detection is belt-and-suspenders. The stamped, signed-under-the-shard-
// manifest spec.ShardRecord.IncompleteMarker field is AUTHORITATIVE: any non-empty value is a
// marker, whatever the kind (so a kind a newer engine adds is still caught), and it needs no
// value. The shape check is the INDEPENDENT fallback for an archive sealed before that field
// existed: it matches a value that is a JSON object whose leading key is one of the known
// sentinels (markerSentinelKeys). value may be the whole restored value or, on the streaming
// path, a bounded leading prefix — either way the object's first key is at the start.
func markerKind(rec spec.ShardRecord, value []byte) string {
	if stamped := strings.TrimSpace(rec.IncompleteMarker); stamped != "" {
		return stamped
	}
	return markerKindFromValue(value)
}

// markerKindFromValue is the shape check: it returns the sentinel key when value is a JSON
// object whose FIRST key is one of the known incompleteness-marker sentinels, else "". It reads
// only the opening brace and the first key through a streaming json.Decoder, so it works on a
// truncated leading prefix (the streaming path) as well as a whole value, and a value that is
// not a JSON object, is empty, or whose first key is not a sentinel is never a false match.
func markerKindFromValue(value []byte) string {
	dec := json.NewDecoder(bytes.NewReader(value))
	tok, err := dec.Token()
	if err != nil {
		return ""
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return ""
	}
	tok, err = dec.Token()
	if err != nil {
		return ""
	}
	key, ok := tok.(string)
	if !ok {
		// An empty object yields the '}' delimiter and a non-object first token yields a
		// non-string; neither is a marker.
		return ""
	}
	if _, isMarker := markerSentinelKeys[key]; isMarker {
		return key
	}
	return ""
}

// noteMarker classifies one just-restored record and, when it is an incompleteness marker,
// counts it and records it for the per-record warning. It is called ONLY after a record has been
// restored (written and value-verified), so IncompleteMarkers stays a subset of Restored: the
// point is to STOP a verified-but-placeholder record being reported as live data, never to fail
// the restore (the value genuinely restored). value is the verified whole value or, on the
// streaming path, a bounded leading prefix.
func (res *Result) noteMarker(rec spec.ShardRecord, key string, value []byte) {
	kind := markerKind(rec, value)
	if kind == "" {
		return
	}
	res.IncompleteMarkers++
	res.Markers = append(res.Markers, RecordMarker{Name: rec.Name, Key: key, Kind: kind})
}

// prefixReader forwards reads from r unchanged while capturing up to limit leading bytes into
// prefix, so the streaming apply can run the incompleteness-marker shape check on a value's start
// WITHOUT buffering the whole (possibly larger-than-memory) value. Once limit bytes are captured
// every later Read is a single length check, so the capture never bounds throughput.
type prefixReader struct {
	r      io.Reader
	prefix []byte
	limit  int
}

func (p *prefixReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 && len(p.prefix) < p.limit {
		want := p.limit - len(p.prefix)
		if want > n {
			want = n
		}
		p.prefix = append(p.prefix, b[:want]...)
	}
	return n, err
}

// codedError is satisfied by an error carrying a normative exit code (format.ExitError's
// ExitCode method). The restore package reads the code through this local interface so it
// stays decoupled from the format reader package, while still preserving a per-record
// failure's true SPEC.md 8.5 class.
type codedError interface{ ExitCode() int }

// recordExitCode returns the normative exit code an error carries, or 0 when it carries
// none (an uncoded I/O failure such as a missing segment object). errors.As unwraps a
// wrapped ExitError (for example one tee'd through the streaming path), so a code set deep
// in the chain is still recovered.
func recordExitCode(err error) int {
	var c codedError
	if errors.As(err, &c) {
		return c.ExitCode()
	}
	return 0
}

// recordFailure appends one failed record and folds its coded exit into IntegrityExit
// (the running maximum), so the apply tracks the most severe per-record integrity class as
// it goes. A failure that carries no coded exit leaves IntegrityExit unchanged.
func (res *Result) recordFailure(name, key string, err error) {
	res.Failed = append(res.Failed, RecordFailure{Name: name, Key: key, Reason: err.Error(), Err: err})
	if code := recordExitCode(err); code > res.IntegrityExit {
		res.IntegrityExit = code
	}
}

// recordReprovision appends one reprovision-type record that was decrypted and hash-verified
// (its recoverability is proven) but whose best-effort courtesy file-write could not be laid
// down as a plain file. It is recorded distinctly from a real failure: the record restores by
// deliberate re-provisioning from the surfaced guidance, never a blind file write, so it never
// makes OK() false and never folds into IntegrityExit. A reprovision record whose VERIFY
// failed is recorded by recordFailure instead, never here, so a corrupted reprovision record
// is never laundered as expected.
func (res *Result) recordReprovision(rec spec.ShardRecord, key string, err error) {
	res.Reprovisioned = append(res.Reprovisioned, RecordReprovision{
		Name:       rec.Name,
		Key:        key,
		SourceType: rec.SourceType,
		Guidance:   GuidanceFor(rec),
		Reason:     err.Error(),
	})
}

// Apply restores the run into the target. It is a no-clobber, two-phase operation: it
// always computes the plan first, and writes only when confirm is true. With confirm
// false it returns the plan and a DryRun result that wrote nothing (the default, so a
// caller must opt in to writing).
//
// On apply, for each planned (non-conflicting) write it reassembles and hash-verifies
// the record's value through the reader (which decrypts with the break-glass identity)
// and writes it to the target. A per-record reassemble, verify or write failure is
// recorded in Result.Failed and the apply proceeds to the next record, so one bad
// record never silently aborts the restore or is laundered as success. Conflicts the
// plan flagged are skipped and counted, never written.
func Apply(r recordReader, t Target, confirm bool) (*Plan, *Result, error) {
	plan, err := MakePlan(r, t)
	if err != nil {
		return nil, nil, err
	}
	res := &Result{Kind: plan.Kind}
	recordConflicts(res, plan)
	if !confirm {
		res.DryRun = true
		return plan, res, nil
	}

	// Index the records by name so a planned write maps back to the record to
	// reassemble. Canonical record order forbids two records sharing one (sourceType,
	// name) (SPEC.md 11.8), and the plan already resolved name collisions on the
	// destination key, so the name is an unambiguous handle here.
	byName := make(map[string]spec.ShardRecord)
	for _, rec := range r.Records() {
		byName[rec.Name] = rec
	}

	applyRecords(plan, byName, r, t, res)
	// Sort failures and reprovision-only records by name for a stable, readable report. Do
	// this before Close so the result is ordered regardless of whether Close returns an error.
	sort.Slice(res.Failed, func(i, j int) bool { return res.Failed[i].Name < res.Failed[j].Name })
	sort.Slice(res.Reprovisioned, func(i, j int) bool { return res.Reprovisioned[i].Name < res.Reprovisioned[j].Name })
	sort.Slice(res.Markers, func(i, j int) bool { return res.Markers[i].Name < res.Markers[j].Name })
	sort.Slice(res.Unrenderable, func(i, j int) bool { return res.Unrenderable[i].Name < res.Unrenderable[j].Name })
	if cerr := t.Close(); cerr != nil {
		return plan, res, fmt.Errorf("close target: %w", cerr)
	}
	return plan, res, nil
}

// applyRecords writes every planned record into the target, recording each per-record
// reassemble, verify or write failure in res.Failed and proceeding to the next record so
// one bad record never aborts the restore or is laundered as success. It uses the
// streaming path only when both the reader (streamingReader) and the target (StreamTarget)
// opt in and the record is streamable and at least streamThreshold long, restoring a value
// larger than memory in bounded memory; otherwise it buffers the whole value. The per-record plaintext SHA-384 and the
// no-clobber write guard apply on both paths.
//
// applyRecords is the load-all driver: it iterates the materialised plan and delegates each
// record to writeOneRecord, the shared per-record chokepoint (also used by ApplyStreaming),
// whose doc carries the streaming-vs-buffered path selection and the reprovision-only
// classification.
func applyRecords(plan *Plan, byName map[string]spec.ShardRecord, r recordReader, t Target, res *Result) {
	sr, readerStreams := r.(streamingReader)
	st, targetStreams := t.(StreamTarget)
	for _, w := range plan.Writes {
		rec, ok := byName[w.Name]
		if !ok {
			// Defensive: a planned write always corresponds to a record.
			res.Failed = append(res.Failed, RecordFailure{Name: w.Name, Key: w.Key, Reason: "record disappeared between plan and apply"})
			continue
		}
		writeOneRecord(rec, w.Key, r, sr, readerStreams, st, targetStreams, t, res)
	}
}

// recordValueReader is the reassemble-and-verify capability writeOneRecord needs (the load-all
// recordReader and the streaming StreamSource both satisfy it), so the per-record write logic
// is shared by Apply and ApplyStreaming.
type recordValueReader interface {
	RestoreRecord(rec spec.ShardRecord) ([]byte, error)
}

// writeOneRecord reassembles, verifies and writes one already-classified record into the
// target, recording any per-record failure in res (it never aborts the caller's loop). It
// chooses among three paths: a d1 record on the file sink is buffered and TRANSCODED from its
// verified JSON dump into runnable SQL (so the .sql file is turnkey, never raw JSON, and never
// streamed); a streamable record of at least streamThreshold bytes into a streaming target
// flows chunk by chunk for bounded memory on a large value; everything else is the buffered
// whole-value write. The per-record
// plaintext SHA-384 is checked on every path before any bytes are trusted. Shared by Apply
// (load-all) and ApplyStreaming.
//
// A reprovision-type record (workers, cf-config, stream, images, artifacts) is always taken
// through the buffered path, never the streaming path. The streaming path interleaves verify
// and write (a target's WriteStream can fail, for example on the file sink's content vs
// settings/versions path collision, before the value's plaintext hash has been asserted), so
// streaming a reprovision record could leave it unverified yet treated as reprovision-only.
// The buffered path reassembles and hash-verifies the value FIRST (the integrity gate), and
// only then attempts the best-effort courtesy write, so a reprovision record is proven
// recoverable before its write outcome is classified. Reprovision values are bounded (a
// Worker bundle, a config surface, a media inventory), so buffering them is memory-safe.
//
// On the buffered path the verify is the integrity gate for EVERY source type: a reassemble
// or hash failure is a real failure in res.Failed, including for a reprovision record, so a
// corrupted bundle is never laundered as expected. Once the value verifies, the courtesy
// write is attempted; if it fails for a reprovision record (most often the file-sink content
// vs settings/versions path collision), the record is recorded distinctly as reprovision-only
// (verified, restore by deliberate re-provisioning) rather than as a failure, so a restore
// whose only non-written records are reprovision-only by design stays OK and exits zero. A
// write failure for a direct-write source (kv, r2, secrets, d1) stays a real failure.
func writeOneRecord(rec spec.ShardRecord, key string, rv recordValueReader, sr streamingReader, srOK bool, st StreamTarget, stOK bool, t Target, res *Result) {
	name := rec.Name
	if rec.SourceType == spec.SourceD1 && t.Kind() == "file" {
		value, rerr := rv.RestoreRecord(rec)
		if rerr != nil {
			res.recordFailure(name, key, rerr)
			return
		}
		out, terr := maybeTranscodeD1(value)
		if terr != nil {
			res.recordFailure(name, key, terr)
			return
		}
		if werr := t.Write(key, out); werr != nil {
			res.recordFailure(name, key, werr)
			return
		}
		res.Restored++
		// Count the verified value bytes (not the transcoded SQL length) so BytesRestored stays
		// the "value bytes restored" metric whether or not a record was transcoded.
		res.BytesRestored += int64(len(value))
		// Classify an incompleteness marker from the stamped field or the verified value shape,
		// so a d1 record whose dump is actually a sentinel placeholder is surfaced rather than
		// written out as a real .sql file.
		res.noteMarker(rec, key, value)
		// And, separately, whether this release could render the body at all. A record can be
		// both: a sentinel placeholder stamped with a format label from a newer engine is two
		// distinct things wrong, and the operator needs to be told both.
		res.noteUnrenderable(rec, key, value)
		return
	}
	if srOK && stOK && rec.PlaintextSize >= streamThreshold && sr.IsStreamable(rec) && !spec.ReprovisionSourceType(rec.SourceType) {
		n, prefix, serr := applyStream(sr, st, rec, key)
		if serr != nil {
			res.recordFailure(name, key, serr)
			return
		}
		res.Restored++
		res.BytesRestored += n
		// Classify an incompleteness marker from the stamped field or the captured leading bytes,
		// so a verified-but-placeholder value restored through the bounded-memory streaming path
		// is still surfaced (not a silent false-green).
		res.noteMarker(rec, key, prefix)
		return
	}
	value, rerr := rv.RestoreRecord(rec)
	if rerr != nil {
		// Integrity gate: a reassemble, decrypt or plaintext-hash failure is a real failure for
		// every source type, including a reprovision record, so corrupted bytes are never
		// laundered into the reprovision-only list.
		res.recordFailure(name, key, rerr)
		return
	}
	if werr := t.Write(key, value); werr != nil {
		if spec.ReprovisionSourceType(rec.SourceType) {
			// The bytes are verified (recoverability proven); only the best-effort courtesy
			// file-write could not be laid down, most often the file-sink path collision between
			// a Worker's content record and its settings/versions siblings. A reprovision record
			// restores by deliberate re-provisioning, not a plain file write, so this is reported
			// distinctly and is not a failure.
			res.recordReprovision(rec, key, werr)
			return
		}
		res.recordFailure(name, key, werr)
		return
	}
	res.Restored++
	res.BytesRestored += int64(len(value))
	// Classify an incompleteness marker from the stamped field or the verified value shape, so a
	// sentinel placeholder written through the buffered path (any sink, including env and discard)
	// is surfaced rather than presented as the source's live data.
	res.noteMarker(rec, key, value)
}

// maybeTranscodeD1 returns runnable SQL for a recognised downpipe D1 JSON dump, or the value
// verbatim for any other body. A recognised-but-malformed D1 body returns an error so a broken
// dump fails loudly rather than writing un-runnable SQL to disk.
func maybeTranscodeD1(value []byte) ([]byte, error) {
	sql, ok, err := transcodeD1(value)
	if err != nil {
		return nil, err
	}
	if ok {
		return sql, nil
	}
	return value, nil
}

// StreamSource is the bounded-memory read side of a verified run: a streaming record iterator
// plus the per-record reassemble-and-verify, so ApplyStreaming restores a run without ever
// materialising the whole record set. *format.StreamReader satisfies it; a source that also
// implements streamingReader (IsStreamable + RestoreRecordTo) is offered the per-record
// streaming path for values larger than memory.
type StreamSource interface {
	EachRecord(func(spec.ShardRecord) error) error
	RestoreRecord(rec spec.ShardRecord) ([]byte, error)
}

// ApplyStreaming restores a verified run into the target in BOUNDED MEMORY. It iterates the
// records one at a time (never holding the whole set, unlike Apply which holds the reader's
// slice plus the planner's byName map and OOMs a large archive), classifies each against the
// target's existing keys and the keys this run has already claimed (the no-clobber plan), and
// -- when confirm is true -- reassembles, verifies and writes each writable record immediately
// before moving on. Memory is bounded by the running no-clobber key sets and one record at a
// time, not the record count.
//
// confirm false is a dry run: every record is classified (so the conflict report is complete)
// and nothing is written. The returned Plan carries WriteCount, Conflicts, Reprovision,
// HasD1File and the totals but NOT the per-record Writes slice (which would be O(records)); the
// caller reports the planned-write count through WriteCount.
func ApplyStreaming(src StreamSource, t Target, confirm bool) (*Plan, *Result, error) {
	existing, err := t.Existing()
	if err != nil {
		return nil, nil, fmt.Errorf("enumerate target state: %w", err)
	}
	plan := &Plan{Kind: t.Kind()}
	res := &Result{Kind: t.Kind()}
	// claimed is the within-run no-clobber set (the only unavoidable O(distinct keys) state);
	// it is far smaller than the whole record metadata the load-all path holds.
	claimed := make(map[string]struct{})
	sr, readerStreams := src.(streamingReader)
	st, targetStreams := t.(StreamTarget)

	iterErr := src.EachRecord(func(rec spec.ShardRecord) error {
		plan.TotalRecords++
		key, conflict := classifyRecord(t, rec, existing, claimed)
		if conflict != nil {
			plan.Conflicts = append(plan.Conflicts, *conflict)
			return nil
		}
		claimed[key] = struct{}{}
		plan.WriteCount++
		plan.TotalBytes += rec.PlaintextSize
		annotateD1(plan, t, rec, key)
		annotateReprovision(plan, rec, key)
		if confirm {
			writeOneRecord(rec, key, src, sr, readerStreams, st, targetStreams, t, res)
		}
		return nil
	})
	recordConflicts(res, plan)

	if !confirm {
		res.DryRun = true
		return plan, res, iterErr
	}
	// Sort failures and reprovision-only records for a stable report, then close the target
	// (flush) even if the stream stopped on a fatal manifest error, but let that fatal error
	// take precedence on return.
	sort.Slice(res.Failed, func(i, j int) bool { return res.Failed[i].Name < res.Failed[j].Name })
	sort.Slice(res.Reprovisioned, func(i, j int) bool { return res.Reprovisioned[i].Name < res.Reprovisioned[j].Name })
	sort.Slice(res.Markers, func(i, j int) bool { return res.Markers[i].Name < res.Markers[j].Name })
	sort.Slice(res.Unrenderable, func(i, j int) bool { return res.Unrenderable[i].Name < res.Unrenderable[j].Name })
	cerr := t.Close()
	if iterErr != nil {
		return plan, res, iterErr
	}
	if cerr != nil {
		return plan, res, fmt.Errorf("close target: %w", cerr)
	}
	return plan, res, nil
}
