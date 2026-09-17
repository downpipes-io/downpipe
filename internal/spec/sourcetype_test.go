package spec

import "testing"

// The supported set is exactly the nine types a conformant downpipe/0.1.0 writer emits
// (SPEC.md 12.1); the reserved-but-unsupported types and any garbage are not in it.
func TestIsKnownSourceType(t *testing.T) {
	known := []string{SourceKV, SourceR2, SourceSecrets, SourceD1, SourceWorkers, SourceCFConfig, SourceStream, SourceImages, SourceArtifacts}
	for _, s := range known {
		if !IsKnownSourceType(s) {
			t.Errorf("IsKnownSourceType(%q) = false, want true", s)
		}
	}
	// The literal values are the frozen wire strings; assert them so a rename is caught.
	if SourceKV != "kv" || SourceR2 != "r2" || SourceSecrets != "secrets" || SourceD1 != "d1" || SourceWorkers != "workers" || SourceCFConfig != "cf-config" ||
		SourceStream != "stream" || SourceImages != "images" || SourceArtifacts != "artifacts" {
		t.Fatalf("source-type literals drifted: %q %q %q %q %q %q %q %q %q", SourceKV, SourceR2, SourceSecrets, SourceD1, SourceWorkers, SourceCFConfig, SourceStream, SourceImages, SourceArtifacts)
	}

	unknown := []string{"", "KV", "durable_object", "vectorize", "queue", "workers ", "cfconfig"}
	for _, s := range unknown {
		if IsKnownSourceType(s) {
			t.Errorf("IsKnownSourceType(%q) = true, want false", s)
		}
	}
}

// Workers, cf-config, stream, images and artifacts restore by re-provisioning or replay
// guidance; the direct-write sources do not.
func TestReprovisionSourceType(t *testing.T) {
	for _, s := range []string{SourceWorkers, SourceCFConfig, SourceStream, SourceImages, SourceArtifacts} {
		if !ReprovisionSourceType(s) {
			t.Errorf("ReprovisionSourceType(%q) = false, want true", s)
		}
	}
	for _, s := range []string{SourceKV, SourceR2, SourceSecrets, SourceD1, "", "durable_object"} {
		if ReprovisionSourceType(s) {
			t.Errorf("ReprovisionSourceType(%q) = true, want false", s)
		}
	}
}
