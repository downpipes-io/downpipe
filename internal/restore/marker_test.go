package restore

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// An incompleteness marker is a valid, hash-verifying record whose VALUE is a sentinel JSON
// placeholder (kinds _unavailable, _skipped, _pending, _truncated, _refused) that the engine
// wrote because a source was only partially available at backup time. Before this fix the
// offline restore decrypted it, passed its hash, WROTE it as the real KV/config/secret/R2 value
// and counted it as Restored with OK()=true and exit 0 — a silent false-green that hands the
// operator a `{"_skipped":…}` blob as live data during a DR. These tests pin that a marker is now
// detected (by the stamped field OR the value shape), counted in Result.IncompleteMarkers,
// surfaced per-record, and that a normal record is untouched. The value STILL restores (it
// genuinely did); the point is to stop the false-green, not to fail the restore.

// TestApplyShapeMarkerBufferedPath pins the shape-check fallback on the buffered path (fakeReader
// is not a streamingReader, so Apply reassembles the whole value): a record whose value is a
// `{"_skipped":…}` sentinel is detected as a marker, counted, and named with its kind, while a
// sibling record of genuine data is not. The marker value is STILL written to the target — the
// data restored; OK() stays true — so the fix stops the false-green without dropping data.
func TestApplyShapeMarkerBufferedPath(t *testing.T) {
	dir := t.TempDir()
	const markerVal = `{"_skipped":"the kv namespace was unavailable at backup time"}`
	r := rdr([2]string{"real", "genuine restored data"}, [2]string{"partial", markerVal})
	target := NewDirTarget(dir)

	_, res, err := Apply(r, target, true)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !res.OK() {
		t.Fatalf("a marker must NOT be a failure (the value restored), got Failed=%+v", res.Failed)
	}
	if res.Restored != 2 {
		t.Fatalf("both records restore (the marker included), got Restored=%d", res.Restored)
	}
	if res.IncompleteMarkers != 1 {
		t.Fatalf("exactly one record is an incompleteness marker, got IncompleteMarkers=%d markers=%+v", res.IncompleteMarkers, res.Markers)
	}
	if len(res.Markers) != 1 || res.Markers[0].Name != "partial" || res.Markers[0].Kind != "_skipped" {
		t.Fatalf("the marker must name the record and kind, got %+v", res.Markers)
	}
	// The marker value is genuinely on disk: the fix surfaces it, it does not drop it.
	got, err := os.ReadFile(filepath.Join(dir, "partial"))
	if err != nil || string(got) != markerVal {
		t.Fatalf("the marker value must still be written (restored), got %q err=%v", got, err)
	}
}

// TestApplyStampedMarkerFieldAuthoritative pins the authoritative path: a record carrying the
// stamped spec.ShardRecord.IncompleteMarker field is detected as a marker even though its value
// is NOT a sentinel-shaped JSON object, proving the field is honoured independently of the shape
// check and that its kind (here _unavailable) is reported. A sibling normal record — no field, no
// sentinel shape — is not a marker.
func TestApplyStampedMarkerFieldAuthoritative(t *testing.T) {
	dir := t.TempDir()
	// Value is deliberately NOT a sentinel-shaped object, so only the stamped field can classify it.
	const stampedVal = "this is plain text, not a JSON sentinel object"
	r := &fakeReader{
		values: map[string][]byte{"stamped": []byte(stampedVal), "normal": []byte("real data")},
		failOn: map[string]bool{},
		recs: []spec.ShardRecord{
			{SourceType: "kv", Name: "stamped", RecordID: "recordid00000000", PlaintextSize: int64(len(stampedVal)), IncompleteMarker: "_unavailable"},
			{SourceType: "kv", Name: "normal", RecordID: "recordid00000001", PlaintextSize: int64(len("real data"))},
		},
	}
	target := NewDirTarget(dir)

	_, res, err := Apply(r, target, true)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Restored != 2 || !res.OK() {
		t.Fatalf("both records restore and neither fails, got Restored=%d Failed=%+v", res.Restored, res.Failed)
	}
	if res.IncompleteMarkers != 1 {
		t.Fatalf("the stamped record is the only marker, got IncompleteMarkers=%d markers=%+v", res.IncompleteMarkers, res.Markers)
	}
	if len(res.Markers) != 1 || res.Markers[0].Name != "stamped" || res.Markers[0].Kind != "_unavailable" {
		t.Fatalf("the stamped field must be authoritative and report its kind, got %+v", res.Markers)
	}
}

// TestApplyNormalRecordsNoMarkers is the backward-compatibility / no-false-positive anchor: an
// apply over ordinary records — including a genuine JSON value whose keys are NOT sentinels —
// reports zero incompleteness markers, so an existing archive restores exactly as before with the
// exit unchanged.
func TestApplyNormalRecordsNoMarkers(t *testing.T) {
	dir := t.TempDir()
	r := rdr(
		[2]string{"plain", "just some bytes"},
		[2]string{"config.json", `{"name":"prod","_skippedButNotLeading":true}`}, // sentinel not the leading key
		[2]string{"nested/x", `{"region":"apac"}`},
	)
	target := NewDirTarget(dir)

	_, res, err := Apply(r, target, true)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Restored != 3 || !res.OK() {
		t.Fatalf("all normal records restore, got Restored=%d Failed=%+v", res.Restored, res.Failed)
	}
	if res.IncompleteMarkers != 0 || len(res.Markers) != 0 {
		t.Fatalf("normal records must produce no markers, got IncompleteMarkers=%d markers=%+v", res.IncompleteMarkers, res.Markers)
	}
}

// TestApplyStreamingShapeMarkerViaStreamReader proves the shape check fires on the BOUNDED-MEMORY
// streaming path over a REAL encrypted, signed archive: format.StreamOpen verifies the run and
// ApplyStreaming restores a streamable kv record (non-gzip, non-packed) through DirTarget's
// WriteStream, where the value is never materialised — the marker is caught from the captured
// leading-bytes prefix instead. The `{"_truncated":…}` record is flagged; the whole-data record
// is not; and the marker value is still written byte-for-byte (it restored).
func TestApplyStreamingShapeMarkerViaStreamReader(t *testing.T) {
	store := memStore{}
	const markerVal = `{"_truncated":"the crawl window closed before this object finished streaming"}`
	values := map[string]string{
		"whole":   "genuine restored data through the streaming path",
		"partial": markerVal,
	}
	identity, verifier, runID := buildArchive(t, store, "dp_marker_stream", "kv", values)

	sr, err := format.StreamOpen(store, runID, identity, verifier, format.Options{})
	if err != nil {
		t.Fatalf("StreamOpen: %v", err)
	}

	dir := t.TempDir()
	target := NewDirTarget(dir) // DirTarget is a StreamTarget, so a streamable record uses WriteStream
	_, res, err := ApplyStreaming(sr, target, true)
	if err != nil {
		t.Fatalf("ApplyStreaming: %v", err)
	}
	if res.Restored != len(values) || !res.OK() {
		t.Fatalf("every record restores through streaming, got Restored=%d Failed=%+v", res.Restored, res.Failed)
	}
	if res.IncompleteMarkers != 1 {
		t.Fatalf("the streamed marker must be caught via the prefix shape check, got IncompleteMarkers=%d markers=%+v", res.IncompleteMarkers, res.Markers)
	}
	if len(res.Markers) != 1 || res.Markers[0].Name != "partial" || res.Markers[0].Kind != "_truncated" {
		t.Fatalf("the streamed marker must name the record and kind, got %+v", res.Markers)
	}
	// The value restored byte-for-byte despite the warning (streaming write completed and verified).
	got, err := os.ReadFile(filepath.Join(dir, "partial"))
	if err != nil || string(got) != markerVal {
		t.Fatalf("the streamed marker value must be written (restored), got %q err=%v", got, err)
	}
}

// TestApplyEnvSinkMarker covers the env sink (SPEC.md 12.6): a dotenv record whose value is a
// sentinel is detected as a marker and named, while a genuine secret line is not — so an operator
// restoring secrets to a .env file is warned that a variable holds a placeholder, not the real
// value, instead of silently loading `{"_pending":…}` as a live secret.
func TestApplyEnvSinkMarker(t *testing.T) {
	var buf bytes.Buffer
	const markerVal = `{"_pending":"the secrets store was still enumerating at backup time"}`
	r := rdr([2]string{"REAL_TOKEN", "s3cr3t"}, [2]string{"KV_STATUS", markerVal})
	target := NewEnvTarget(&buf, nil)

	_, res, err := Apply(r, target, true)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Restored != 2 || !res.OK() {
		t.Fatalf("both env records restore, got Restored=%d Failed=%+v", res.Restored, res.Failed)
	}
	if res.IncompleteMarkers != 1 || len(res.Markers) != 1 || res.Markers[0].Name != "KV_STATUS" || res.Markers[0].Kind != "_pending" {
		t.Fatalf("the env-sink marker must be detected and named, got IncompleteMarkers=%d markers=%+v", res.IncompleteMarkers, res.Markers)
	}
	if !strings.Contains(buf.String(), "KV_STATUS=") {
		t.Fatalf("the env marker line must still be written (it restored), got: %q", buf.String())
	}
}

// TestMarkerKindShapeCheck is a focused unit table over markerKindFromValue: every sentinel key
// is detected as the LEADING key of a JSON object, and non-marker shapes (plain text, a JSON
// array, an empty object, a sentinel that is not the leading key, a sentinel-looking substring)
// are never false matches. This is the false-positive discipline that keeps the shape-check
// fallback from mis-flagging genuine data in a pre-field archive.
func TestMarkerKindShapeCheck(t *testing.T) {
	markers := map[string]string{
		"unavailable": `{"_unavailable":"x"}`,
		"skipped":     `{"_skipped":"x"}`,
		"pending":     `{"_pending":true}`,
		"truncated":   `{"_truncated":123}`,
		"refused":     `{"_refused":"policy"}`,
		"leading":     `{"_skipped":"x","extra":1}`, // sentinel is the leading key, still a marker
	}
	for name, v := range markers {
		if got := markerKindFromValue([]byte(v)); got == "" {
			t.Errorf("%s: %q must be detected as a marker, got kind %q", name, v, got)
		}
	}
	notMarkers := map[string]string{
		"plain_text":        "just some bytes",
		"empty":             "",
		"json_array":        `["_skipped"]`,
		"empty_object":      `{}`,
		"not_leading":       `{"name":"x","_skipped":"y"}`,
		"substring":         `{"skipped":"missing underscore"}`,
		"sentinel_as_value": `{"status":"_refused"}`,
		"bare_string":       `"_skipped"`,
	}
	for name, v := range notMarkers {
		if got := markerKindFromValue([]byte(v)); got != "" {
			t.Errorf("%s: %q must NOT be a marker, got kind %q", name, v, got)
		}
	}
}
