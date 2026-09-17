package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestOfflineImportGraphHasNoVendorSDK enforces the recover-without-vendor promise at the
// binary level (CONTRIBUTING.md "The offline binary imports no network, telemetry or vendor
// SDK"): the entire import graph of ./cmd/downpipe MUST NOT pull in the Cloudflare SDK, an
// analytics or telemetry client, or a general HTTP server or RUM package. A plain S3 GET via
// the standard net/http client is permitted, so the denylist targets vendor and telemetry
// import paths, never the stdlib HTTP client itself. This is the CI guard the contributor
// doc asserts: it runs under `go test ./...`, which CI already executes.
func TestOfflineImportGraphHasNoVendorSDK(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps .: %v", err)
	}
	deps := strings.Split(strings.TrimSpace(string(out)), "\n")

	// Each entry is a substring matched against every import path in the graph. The
	// recover-without-vendor guarantee breaks the moment any of these appears.
	denylist := []string{
		"cloudflare-go",            // the Cloudflare vendor SDK
		"github.com/cloudflare",    // any Cloudflare client
		"go.opentelemetry.io",      // OpenTelemetry tracing/metrics
		"go.opencensus.io",         // OpenCensus telemetry
		"prometheus/client_golang", // Prometheus metrics client
		"getsentry/sentry-go",      // Sentry error telemetry
		"datadog",                  // Datadog telemetry
		"segment.io",               // analytics
		"rum",                      // real-user-monitoring beacons
	}

	for _, dep := range deps {
		for _, bad := range denylist {
			if strings.Contains(dep, bad) {
				t.Errorf("offline import graph contains forbidden package %q (matched denylist entry %q); the offline binary must not import any network, telemetry or vendor SDK", dep, bad)
			}
		}
	}
}
