package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unseal-export from an M-of-N quorum, end to end.
//
// WHY THIS EXISTS. unseal-export declared its own --identity flag instead of registering the shared
// identity-source flags, so it was the one command that took a break-glass key and could not take a split.
// identity_source.go says in as many words that commands register the shared flags "so a new command cannot
// accidentally support only half of the sources and leave split-custody operators back on the disk path",
// and this command was that accident.
//
// It is the worst one to have. unseal-export is the total-account-loss bridge: it opens a sealed
// control-plane export offline so the operator can paste the recovered plaintext into a fresh estate. An
// organisation that split its break-glass key precisely to survive a disaster is the operator most likely
// to be standing at this command, and their only route was `recombine` to identity.key, which writes the
// complete key to disk and leaves it there.
//
// WHAT IS PROVEN. testdata/sealed-export-split is a real engine-sealed export whose ONE recipient is the
// same break-glass identity testdata/custody holds as a 3-of-4 Shamir split, so the quorum route is driven
// against artefacts the console itself produced rather than a Go-side re-implementation of a share file.
// The test recovers the inner export from three of the four shares and requires it to equal both the
// expected inner AND the bytes the --identity route recovers from the same sealed file.

const splitFixtureDir = "testdata/sealed-export-split"

func custodyFixture(name string) string { return filepath.Join("testdata", "custody", name) }

// runUnsealTo runs unseal-export with the given identity-source arguments and returns the recovered bytes.
func runUnsealTo(t *testing.T, identityArgs ...string) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "recovered.json")
	args := make([]string, 0, 8+len(identityArgs))
	args = append(args,
		"--in", filepath.Join(splitFixtureDir, "sealed.json"),
		"--sig", filepath.Join(splitFixtureDir, "sealed.json.sig"),
		"--signer", filepath.Join(splitFixtureDir, "signer.pub"),
		"--out", out,
	)
	if err := cmdUnsealExport(append(args, identityArgs...)); err != nil {
		t.Fatalf("unseal-export %v: %v", identityArgs, err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading the recovered export: %v", err)
	}
	return got
}

// The claim: a split-custody holder can unseal without ever materialising the break-glass key.
func TestUnsealExportFromAQuorumOfShares(t *testing.T) {
	got := runUnsealTo(t,
		"--envelope", custodyFixture("wrapped-identity.txt"),
		"--share", custodyFixture("share-1.txt"),
		"--share", custodyFixture("share-3.txt"),
		"--share", custodyFixture("share-4.txt"),
	)
	want, err := os.ReadFile(filepath.Join(splitFixtureDir, "expected-inner.json"))
	if err != nil {
		t.Fatalf("reading the expected inner: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the export recovered from shares does not match the expected inner (%d bytes vs %d)", len(got), len(want))
	}
}

// The control. Equality with the expected inner alone would not distinguish "the shares recovered the key"
// from "the fixture happens to be openable some other way", so the same sealed file is opened by the file
// route and the two results are required to agree.
func TestUnsealExportFromSharesMatchesTheFileRoute(t *testing.T) {
	fromShares := runUnsealTo(t,
		"--envelope", custodyFixture("wrapped-identity.txt"),
		"--share", custodyFixture("share-1.txt"),
		"--share", custodyFixture("share-3.txt"),
		"--share", custodyFixture("share-4.txt"),
	)
	fromFile := runUnsealTo(t, "--identity", recombinedIdentity(t))
	if !bytes.Equal(fromShares, fromFile) {
		t.Fatal("the share route and the --identity route recovered different exports from the same sealed file")
	}
}

// recombinedIdentity rebuilds the break-glass identity from the committed quorum and returns its path.
//
// WHY IT IS DERIVED RATHER THAN COMMITTED. The first cut of the control read a checked-in
// testdata/sealed-export-split/identity.key. .gitignore's blanket `*.key` meant `git add` on the directory
// skipped it in silence, so the fixture existed only on the machine that wrote it: the test passed there and
// failed everywhere else, including CI. Deriving it keeps no key material in the repo and costs the control
// nothing. The committed shares recombine to this same identity by construction, a recombine that produced
// the wrong key would be refused by the authenticated envelope rather than pass, and the plaintext is pinned
// independently by TestUnsealExportFromAQuorumOfShares against expected-inner.json. What the control tests
// is that the two unseal ROUTES agree, and that is unchanged.
func recombinedIdentity(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "identity.key")
	shares := []string{"share-1.txt", "share-3.txt", "share-4.txt"}
	args := make([]string, 0, 4+2*len(shares))
	args = append(args, "--envelope", custodyFixture("wrapped-identity.txt"), "--out", out)
	for _, share := range shares {
		args = append(args, "--share", custodyFixture(share))
	}
	if err := cmdRecombine(context.Background(), args); err != nil {
		t.Fatalf("recombining the identity from the committed quorum: %v", err)
	}
	return out
}

// Below the quorum it must refuse, and refuse as a CUSTODY failure rather than by opening something wrong.
// Shamir has no error detection of its own: two of four shares silently interpolate to a wrong wrapping key,
// so what stops a bad recovery here is the checksum and the authenticated envelope, not the arithmetic.
func TestUnsealExportBelowTheQuorumRefuses(t *testing.T) {
	err := cmdUnsealExport([]string{
		"--in", filepath.Join(splitFixtureDir, "sealed.json"),
		"--sig", filepath.Join(splitFixtureDir, "sealed.json.sig"),
		"--signer", filepath.Join(splitFixtureDir, "signer.pub"),
		"--envelope", custodyFixture("wrapped-identity.txt"),
		"--share", custodyFixture("share-1.txt"),
		"--share", custodyFixture("share-3.txt"),
	})
	if err == nil {
		t.Fatal("two of four shares unsealed the export, so the threshold is not being enforced")
	}
	if strings.Contains(err.Error(), "not defined") {
		t.Fatalf("the custody flags are not registered on this command: %v", err)
	}
}

// Supplying both an identity file and the custody artefacts is refused rather than resolved by a precedence
// rule, because an operator who passes both has a belief about which key is in use.
func TestUnsealExportRefusesBothSources(t *testing.T) {
	err := cmdUnsealExport([]string{
		"--in", filepath.Join(splitFixtureDir, "sealed.json"),
		"--sig", filepath.Join(splitFixtureDir, "sealed.json.sig"),
		"--signer", filepath.Join(splitFixtureDir, "signer.pub"),
		"--identity", filepath.Join(splitFixtureDir, "identity.key"),
		"--envelope", custodyFixture("wrapped-identity.txt"),
		"--share", custodyFixture("share-1.txt"),
	})
	if err == nil {
		t.Fatal("supplying both an identity file and custody artefacts was accepted")
	}
	if !strings.Contains(err.Error(), "not both") {
		t.Fatalf("expected the both-sources refusal, got: %v", err)
	}
}

// The usage line has to name the share route, or a split holder reading it concludes the command needs a
// file they deliberately do not have.
func TestUnsealExportUsageNamesTheShareRoute(t *testing.T) {
	err := cmdUnsealExport([]string{"--in", filepath.Join(splitFixtureDir, "sealed.json")})
	if err == nil {
		t.Fatal("unseal-export ran with no signature, signer or identity")
	}
	if !strings.Contains(err.Error(), "--share") {
		t.Fatalf("the usage message does not mention the share route: %v", err)
	}
}
