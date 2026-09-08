package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
	"github.com/downpipes-io/downpipe/internal/source"
)

// The --azure-endpoint flag pair, held to exactly what the --s3-endpoint pair is held to: a
// half-supplied destination is a USAGE error and exits 6, and the flag is discoverable in the
// command's own help.
//
// The exit code is the assertion that matters most. This tool's printed table defines 6 as "fix the
// command line" and 1 as "an I/O or unexpected failure this tool did not otherwise classify", and
// defines 2 to 5 as hard failures where a recovery script must stop and investigate. A missing
// container that reached the wire would answer 404 and be classified 11, telling an operator
// mid-recovery that their destination could not be reached when the truth is that they left a flag
// off.

// clearAzureEnvironment removes every Azure credential from the environment for one test, so a
// developer machine that happens to carry one cannot change what a case proves. t.Setenv restores
// them afterwards.
func clearAzureEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("AZURE_STORAGE_KEY", "")
	t.Setenv("AZURE_STORAGE_SAS_TOKEN", "")
	t.Setenv("AZURE_STORAGE_ACCOUNT", "")
}

// testAzureKey is a syntactically valid base64 account key that is NOT a credential.
const testAzureKey = "ZmFrZS1rZXktZm9yLXN0cmluZy10by1zaWduLW9ubHk="

// TestResolveAzureStore covers the Azure branch of storeFlags.resolve with each credential kind.
// NewAzureStore performs NO network I/O at construction, so this stays fully offline.
func TestResolveAzureStore(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
	}{
		{"a storage account key", map[string]string{"AZURE_STORAGE_KEY": testAzureKey}},
		{"a shared access signature", map[string]string{"AZURE_STORAGE_SAS_TOKEN": "sv=2022-11-02&ss=b&sp=r&sig=abc"}},
		{
			"a storage account key with the account named explicitly, for a custom domain",
			map[string]string{"AZURE_STORAGE_KEY": testAzureKey, "AZURE_STORAGE_ACCOUNT": "myaccount"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearAzureEnvironment(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			sf := newAzureStoreFlags("https://myaccount.blob.core.windows.net", "breakglass")
			store, err := sf.resolve()
			if err != nil {
				t.Fatalf("resolve(--azure-endpoint) = %v, want nil", err)
			}
			if _, ok := store.(*source.AzureStore); !ok {
				t.Fatalf("resolve(--azure-endpoint) returned %T, want *source.AzureStore", store)
			}
			// The reader capabilities the format package discovers by type assertion. A store
			// missing one of these still compiles and still opens an archive, and quietly loses
			// streamed segment reads, cancellation or the pruned-run diagnosis.
			if _, ok := store.(format.ReaderStore); !ok {
				t.Error("the Azure store does not satisfy format.ReaderStore, so a large sealed segment would be buffered whole rather than streamed")
			}
			if _, ok := store.(format.ContextStore); !ok {
				t.Error("the Azure store does not satisfy format.ContextStore, so an operator interrupt would not cancel an in-flight fetch")
			}
			if _, ok := store.(format.ListingStore); !ok {
				t.Error("the Azure store does not satisfy format.ListingStore, so a pruned run could not be diagnosed")
			}
			// AND IT MUST NOT BE A MUTATING STORE. The reader's job on a destination is to open
			// an archive somebody else sealed; a break-glass tool that can delete from the
			// destination can destroy the last copy of the data it exists to recover.
			if _, ok := store.(format.MutatingStore); ok {
				t.Error("the Azure store satisfies format.MutatingStore, so the offline tool can DELETE from a customer's container")
			}
		})
	}
}

// TestResolveAzureUsageErrors pins every half-supplied Azure destination to ExitUsage, at the
// resolve() layer where the code is assigned.
func TestResolveAzureUsageErrors(t *testing.T) {
	cases := []struct {
		name      string
		env       map[string]string
		endpoint  string
		container string
		wantIn    string
	}{
		{
			name:     "an endpoint with no container",
			env:      map[string]string{"AZURE_STORAGE_KEY": testAzureKey},
			endpoint: "https://myaccount.blob.core.windows.net",
			wantIn:   "--azure-container is required",
		},
		{
			name:      "an endpoint and container with no credential in the environment",
			endpoint:  "https://myaccount.blob.core.windows.net",
			container: "breakglass",
			wantIn:    "AZURE_STORAGE_KEY",
		},
		{
			name:      "both credentials at once",
			env:       map[string]string{"AZURE_STORAGE_KEY": testAzureKey, "AZURE_STORAGE_SAS_TOKEN": "sv=2022-11-02&sig=abc"},
			endpoint:  "https://myaccount.blob.core.windows.net",
			container: "breakglass",
			wantIn:    "both",
		},
		{
			name:      "a plain http endpoint to a remote host",
			env:       map[string]string{"AZURE_STORAGE_KEY": testAzureKey},
			endpoint:  "http://myaccount.blob.core.windows.net",
			container: "breakglass",
			wantIn:    "https",
		},
		{
			name:      "a storage account key that is not base64",
			env:       map[string]string{"AZURE_STORAGE_KEY": "not base64!!"},
			endpoint:  "https://myaccount.blob.core.windows.net",
			container: "breakglass",
			wantIn:    "base64",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearAzureEnvironment(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			sf := newAzureStoreFlags(tc.endpoint, tc.container)
			_, err := sf.resolve()
			if err == nil {
				t.Fatal("resolve returned no error, want a usage error")
			}
			var ee *format.ExitError
			if !errors.As(err, &ee) || ee.Code != format.ExitUsage {
				t.Fatalf("resolve error is %v, want an *format.ExitError carrying ExitUsage (%d)", err, format.ExitUsage)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("the message does not mention %q, so the operator is not told what to fix: %v", tc.wantIn, err)
			}
		})
	}
}

// TestResolveRefusesTwoEndpoints pins the conflict: an operator who named both destinations has one
// of them wrong, and quietly reading the other means the run that succeeds says nothing about the
// destination they meant.
func TestResolveRefusesTwoEndpoints(t *testing.T) {
	clearAzureEnvironment(t)
	t.Setenv("AZURE_STORAGE_KEY", testAzureKey)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIA-test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret-test")
	sf := newAzureStoreFlags("https://myaccount.blob.core.windows.net", "breakglass")
	sf.s3Endpoint = ptr("https://s3.example.com")
	sf.s3Bucket = ptr("my-bucket")
	_, err := sf.resolve()
	if err == nil {
		t.Fatal("resolve with two endpoints returned no error, want a usage error")
	}
	var ee *format.ExitError
	if !errors.As(err, &ee) || ee.Code != format.ExitUsage {
		t.Fatalf("resolve error is %v, want an *format.ExitError carrying ExitUsage (%d)", err, format.ExitUsage)
	}
	for _, want := range []string{"--s3-endpoint", "--azure-endpoint"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message does not name %q, so the operator cannot see which two flags conflict: %v", want, err)
		}
	}
}

// TestRunAzureFlagsExitUsage drives the SAME conditions through run(), so what is pinned is the
// process exit status a recovery script branches on rather than an intermediate error value.
func TestRunAzureFlagsExitUsage(t *testing.T) {
	silenceOutput(t)
	clearAzureEnvironment(t)

	// An endpoint with no container.
	t.Setenv("AZURE_STORAGE_KEY", testAzureKey)
	if got := run([]string{"inspect", "--run", "ANYRUNID", "--azure-endpoint", "https://myaccount.blob.core.windows.net"}); got != format.ExitUsage {
		t.Errorf("inspect --azure-endpoint with no --azure-container exited %d, want %d (ExitUsage)", got, format.ExitUsage)
	}

	// An endpoint and container with no credential.
	t.Setenv("AZURE_STORAGE_KEY", "")
	got := run([]string{"inspect", "--run", "ANYRUNID", "--azure-endpoint", "https://myaccount.blob.core.windows.net", "--azure-container", "breakglass"})
	if got != format.ExitUsage {
		t.Errorf("inspect --azure-endpoint with no credential exited %d, want %d (ExitUsage)", got, format.ExitUsage)
	}
}

// TestAzureFlagsAreDiscoverable pins that both flags appear in a subcommand's --help. A destination
// the tool can reach and nobody can find is a destination that is not reachable in a disaster, which
// is the only condition this tool runs in.
func TestAzureFlagsAreDiscoverable(t *testing.T) {
	// Every command that opens an archive defines the store flags through addStoreFlags, so the
	// help of any one of them proves the pair is defined; all of them are checked so a command
	// that stopped calling addStoreFlags is caught here rather than by an operator.
	for _, cmd := range []string{"inspect", "keys", "verify", "attest", "restore", "prune"} {
		t.Run(cmd, func(t *testing.T) {
			out := captureStderr(t, func() { _ = run([]string{cmd, "--help"}) })
			for _, flag := range []string{"-azure-endpoint", "-azure-container"} {
				if !strings.Contains(out, flag) {
					t.Errorf("%s --help does not list %s, so the Azure destination is undiscoverable from the tool itself", cmd, flag)
				}
			}
		})
	}
}

// TestAzureDestinationIsDescribedInAReceipt pins that the prune receipt names an Azure destination
// rather than falling through to "unknown destination". The receipt is a plain file an operator may
// keep, attach to a ticket or hand to an auditor, and one that cannot say which destination it
// describes is worth less than one that can.
func TestAzureDestinationIsDescribedInAReceipt(t *testing.T) {
	sf := newAzureStoreFlags("https://myaccount.blob.core.windows.net", "breakglass")
	got := sf.describe()
	want := "azure https://myaccount.blob.core.windows.net/breakglass"
	if got != want {
		t.Fatalf("describe() = %q, want %q", got, want)
	}
	if !sf.supplied() {
		t.Error("supplied() is false for an Azure destination, so a command would report a source as missing when one was named")
	}
}
