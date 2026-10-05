package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
)

// These drive --signer-fingerprint against an archive served by an in-process S3 or Azure server,
// because reading straight from the destination is a documented recovery route. A directory store
// reports a missing file with fs.ErrNotExist; a remote store reports a 404. SPEC.md 9.1 says an
// absent bundled copy is a usage error (6) on every source, so the 404 for the OBJECT has to reach
// the same answer. A 404 for the bucket or container is a destination the reader could not read,
// and keeps the unreachable code (11).

// archiveServer serves the files of dir under /<container>/<key>, the path-style address both
// stores send. A missing object answers with the store's own not-found shape. When missingContainer
// is set, every request answers as though the bucket or container does not exist.
func archiveServer(t *testing.T, dir, container string, azure, missingContainer bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, ok := strings.CutPrefix(r.URL.Path, "/"+container+"/")
		if missingContainer || !ok {
			notFound(w, azure, true)
			return
		}
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(key)))
		if err != nil {
			notFound(w, azure, false)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// notFound writes a 404 in the shape S3 or Azure uses: S3 names the code in an XML body, Azure in
// the x-ms-error-code header.
func notFound(w http.ResponseWriter, azure, container bool) {
	if azure {
		code := "BlobNotFound"
		if container {
			code = "ContainerNotFound"
		}
		w.Header().Set("x-ms-error-code", code)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	code := "NoSuchKey"
	if container {
		code = "NoSuchBucket"
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>" + code + "</Code><Message>not found</Message></Error>"))
}

// remoteArgs returns the source flags for a server, and sets the credential the store reads.
func remoteArgs(t *testing.T, srvURL string, azure bool) []string {
	t.Helper()
	if azure {
		t.Setenv("AZURE_STORAGE_ACCOUNT", "myaccount")
		t.Setenv("AZURE_STORAGE_KEY", "dGVzdC1henVyZS1rZXktZm9yLXNpZ25pbmctb25seQ==")
		t.Setenv("AZURE_STORAGE_SAS_TOKEN", "")
		return []string{"--azure-endpoint", srvURL, "--azure-container", "breakglass"}
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	return []string{"--s3-endpoint", srvURL, "--s3-bucket", "breakglass"}
}

func TestSignerFingerprintOverARemoteSource(t *testing.T) {
	for _, azure := range []bool{false, true} {
		name := "s3"
		if azure {
			name = "azure"
		}
		t.Run(name, func(t *testing.T) {
			dir, runID, idPath, _, pin := sealedArchive(t, "remote "+name)
			base := []string{"verify", "--run", runID, "--identity", idPath, "--signer-fingerprint", pin, "--acknowledge-no-rollback-pin"}

			// The copy is there: the pinned route verifies over the remote source too.
			srv := archiveServer(t, dir, "breakglass", azure, false)
			if code, stderr := runCmd(t, append(append([]string{}, base...), remoteArgs(t, srv.URL, azure)...)...); code != 0 {
				t.Fatalf("verify --signer-fingerprint over %s = %d, want 0\n%s", name, code, stderr)
			}

			// The copy is absent: the store answers 404 for the object. That is exit 6 and names
			// --signer, as it is on a directory, and it does not open with a wrong-bucket hint.
			if err := os.Remove(bundledSignerPath(dir)); err != nil {
				t.Fatal(err)
			}
			code, stderr := runCmd(t, append(append([]string{}, base...), remoteArgs(t, srv.URL, azure)...)...)
			if code != format.ExitUsage {
				t.Fatalf("verify --signer-fingerprint over %s with no bundled copy = %d, want %d (ExitUsage)\n%s", name, code, format.ExitUsage, stderr)
			}
			for _, want := range []string{"has no", "--signer with signer.pub"} {
				if !strings.Contains(stderr, want) {
					t.Errorf("the absent-copy message over %s does not say %q\n%s", name, want, stderr)
				}
			}
			if strings.Contains(stderr, "not found: check") {
				t.Errorf("the absent-copy message over %s carries the store's wrong-destination hint\n%s", name, stderr)
			}

			// The bucket or container itself is absent. That is not a missing copy: the reader could
			// not read the destination, so it keeps the unreachable code.
			gone := archiveServer(t, dir, "breakglass", azure, true)
			code, stderr = runCmd(t, append(append([]string{}, base...), remoteArgs(t, gone.URL, azure)...)...)
			if code != format.ExitUnreachable {
				t.Fatalf("verify --signer-fingerprint over %s with no bucket or container = %d, want %d (ExitUnreachable)\n%s", name, code, format.ExitUnreachable, stderr)
			}
		})
	}
}
