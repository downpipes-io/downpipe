package main

import (
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/restore"
)

// TestReportMetadataNotKeptIsLoud: a record whose KV or R2 metadata the target could not keep
// must get a WARNING line with its name, key and fields, and the count must get a WARNING
// summary, so the loss is never silent.
func TestReportMetadataNotKeptIsLoud(t *testing.T) {
	plan := &restore.Plan{Kind: "env", WriteCount: 2}
	result := &restore.Result{Kind: "env", Restored: 2, MetadataUnapplied: []restore.RecordMetadataUnapplied{{
		Name: "API_TOKEN", Key: "API_TOKEN", SourceType: "kv",
		Fields: []string{"kv.metadata", "kv.expiration"},
		Reason: "the env target has no place to keep metadata; restore with --sink file to keep it in a sidecar",
	}}}
	_, stderr := captureOutput(t, func() {
		reportRestoreOutcome(restore.NewEnvTarget(&strings.Builder{}, nil), plan, result, true)
	})
	for _, want := range []string{
		`WARNING metadata NOT kept [kv] "API_TOKEN" -> "API_TOKEN": kv.metadata, kv.expiration: the env target has no place to keep metadata`,
		"WARNING: 1 of 2 restored record(s) carry source metadata",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr must carry %q, got:\n%s", want, stderr)
		}
	}
}

// TestReportMetadataSidecarsKept: the file sink says once where it kept the metadata, and
// prints no warning when it kept all of it.
func TestReportMetadataSidecarsKept(t *testing.T) {
	plan := &restore.Plan{Kind: "file", WriteCount: 3}
	result := &restore.Result{Kind: "file", Restored: 3, MetadataSidecars: 2}
	_, stderr := captureOutput(t, func() {
		reportRestoreOutcome(restore.NewDirTarget(t.TempDir()), plan, result, true)
	})
	if !strings.Contains(stderr, "kept the source metadata of 2 record(s) in a sidecar next to each value (<key>.downpipe-meta.json") {
		t.Fatalf("stderr must name the sidecars, got:\n%s", stderr)
	}
	if strings.Contains(stderr, "WARNING") {
		t.Fatalf("no metadata was lost, so no warning is due, got:\n%s", stderr)
	}
}
