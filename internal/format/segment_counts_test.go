package format

import (
	"bytes"
	"strings"
	"testing"

	"github.com/downpipes-io/downpipe/internal/crypto"
	"github.com/downpipes-io/downpipe/internal/spec"
)

// TestValidateCountsArrayPaths pins the "[]" path form: each array element is checked,
// the concrete index is named in the error, and a case-colliding key is refused at an
// intermediate object as well as at the last one.
func TestValidateCountsArrayPaths(t *testing.T) {
	paths := recordCountPaths
	accept := []string{
		`{"plaintextSize":3,"segments":[]}`,
		`{"plaintextSize":3,"segments":[{"chunkRange":[0,1],"packed":null}]}`,
		`{"plaintextSize":3,"segments":[{"chunkRange":[0,1],"packed":{"offset":0,"length":3}}]}`,
		`{"plaintextSize":3}`,
	}
	for _, raw := range accept {
		if err := validateCounts([]byte(raw), paths...); err != nil {
			t.Errorf("%s: want accepted, got %v", raw, err)
		}
	}
	refuse := []struct{ raw, want string }{
		{`{"segments":[{"chunkRange":[0,1],"packed":{"offset":"0","length":3}}]}`, `"segments[0].packed.offset"`},
		{`{"segments":[{"chunkRange":[0,1]},{"chunkRange":[0,1],"packed":{"offset":0,"length":-1}}]}`, `"segments[1].packed.length"`},
		{`{"segments":[{"chunkRange":[0,"1"]}]}`, `"segments[0].chunkRange[1]"`},
		{`{"segments":[{"chunkRange":[0,9007199254740992]}]}`, `"segments[0].chunkRange[1]"`},
		{`{"segments":[{"chunkRange":[0,1.5]}]}`, `"segments[0].chunkRange[1]"`},
		{`{"segments":[{"chunkRange":"0-1"}]}`, `must be an array`},
		{`{"segments":{"chunkRange":[0,1]}}`, `must be an array`},
		{`{"segments":[{"chunkRange":[0,1]}],"Segments":[{"chunkRange":[0,-1]}]}`, `differs only in case`},
		{`{"segments":[{"chunkRange":[0,1],"packed":{"offset":0,"Offset":-1}}]}`, `differs only in case`},
	}
	for _, c := range refuse {
		err := validateCounts([]byte(c.raw), paths...)
		if err == nil {
			t.Errorf("%s: want refused, was accepted", c.raw)
			continue
		}
		if code, ok := exitCodeOf(err); !ok || code != ExitUsage {
			t.Errorf("%s: want exit %d, got code %d ok=%v: %v", c.raw, ExitUsage, code, ok, err)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want the error to name %s, got %v", c.raw, c.want, err)
		}
	}
	// A re-cased intermediate object is refused too: encoding/json matches it.
	err := validateCounts([]byte(`{"freshness":{"runlogIndex":1},"Freshness":{"runlogIndex":-5}}`), "freshness.runlogIndex")
	if err == nil || !strings.Contains(err.Error(), "differs only in case") {
		t.Errorf("a re-cased intermediate object must be refused, got %v", err)
	}
}

// TestSegmentCountsAreExit6AtOpen proves SPEC.md 11.3 for the segment counts through the
// whole reader: a packed offset or length, or a chunkRange endpoint, in the wrong form is
// refused by Open with exit 6. Each case re-seals the shard with one token of one record
// line changed and re-signs the root over the new shard hash, so the signature and shard
// hash gates pass and only the numeric-form gate can refuse it. Before, a string value
// failed later as an uncoded parse error, and a negative or over-ceiling value was
// accepted at open. The control re-seals with no change and must open, so the refusals
// are caused by the token and not by the re-seal.
func TestSegmentCountsAreExit6AtOpen(t *testing.T) {
	vs := vectorSpec{dpID: "dp_segcounts", records: []recordSpec{
		{name: "object-a", srcType: "r2", value: []byte("first packed value"), packGroup: 1},
		{name: "object-b", srcType: "r2", value: []byte("second packed value"), packGroup: 1},
	}}
	cases := []struct {
		name     string
		from, to string
	}{
		{"control", "", ""},
		{"offset as a string", `"offset":0`, `"offset":"0"`},
		{"negative length", `"length":18`, `"length":-1`},
		{"chunkRange endpoint as a string", `"chunkRange":[0,1]`, `"chunkRange":[0,"1"]`},
		{"chunkRange endpoint above 2^53-1", `"chunkRange":[0,1]`, `"chunkRange":[0,9007199254740992]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, identity, verifier, signer := buildArchiveSpec(t, vs)
			resealShardLine(t, store, signer, tc.from, tc.to)
			_, err := Open(store, vecRunID, identity, verifier, Options{})
			if tc.from == "" {
				if err != nil {
					t.Fatalf("the unchanged re-seal must open: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Open accepted a record line with %s", tc.name)
			}
			if code, ok := exitCodeOf(err); !ok || code != ExitUsage {
				t.Fatalf("want exit %d, got code %d ok=%v: %v", ExitUsage, code, ok, err)
			}
		})
	}
}

// resealShardLine opens the vector's single shard, replaces the first from token in the
// record lines with to, re-seals the shard and re-signs the root over the new hash. An
// empty from re-seals the plaintext unchanged. The token must be present, so a case can
// never pass because its token did not match.
func resealShardLine(t *testing.T, store memStore, signer *crypto.HybridSigner, from, to string) {
	t.Helper()
	runIDBytes, err := spec.DecodeULID(vecRunID)
	if err != nil {
		t.Fatal(err)
	}
	wrapKey := crypto.DeriveManifestWrapKey(crypto.DeriveMK(fixedMaster(), runIDBytes), runIDBytes, "00000")
	shardKey := runKey(vecRunID, "manifest/00000.dpe")
	body, err := spec.UnframeContainer(spec.MagicDpe, store[shardKey])
	if err != nil {
		t.Fatal(err)
	}
	plain, err := crypto.OpenStream(toKey(wrapKey), body)
	if err != nil {
		t.Fatal(err)
	}
	if from != "" {
		if !bytes.Contains(plain, []byte(from)) {
			t.Fatalf("token %s is not in the shard plaintext:\n%s", from, plain)
		}
		plain = bytes.Replace(plain, []byte(from), []byte(to), 1)
	}
	sealedBody, err := crypto.SealStream(toKey(wrapKey), plain, fixedNonce())
	if err != nil {
		t.Fatal(err)
	}
	sealed := spec.FrameContainer(spec.MagicDpe, sealedBody)
	store[shardKey] = sealed

	rootKey := runKey(vecRunID, "root.manifest.json")
	root, err := ParseRoot(store[rootKey])
	if err != nil {
		t.Fatal(err)
	}
	root.Shards[0].SHA384 = SHA384Hex(sealed)
	canonical, sig, err := SignRoot(root, signer)
	if err != nil {
		t.Fatal(err)
	}
	store[rootKey] = canonical
	store[runKey(vecRunID, "root.manifest.json.sig")] = []byte(B64Encode(sig))
}
