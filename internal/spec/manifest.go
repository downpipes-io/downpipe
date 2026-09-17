package spec

import "encoding/json"

// This file defines the on-disk JSON shapes of a downpipe/0.1.0 archive: the cleartext
// root manifest that bootstraps recovery, and the per-record line of the encrypted
// shard manifest. Binary fields are base64url no-pad strings and hashes are bare
// lowercase hex strings (SPEC.md 11.4, 11.8). Keeping them as strings makes the
// canonical JSON used for signing straightforward, and keeps this package free of
// crypto imports (decision D10).

// RootManifest is run/<runId>/root.manifest.json: small cleartext metadata that lets
// a holder of a recipient identity bootstrap the whole archive. It carries no payload,
// no plaintext key material, and no reconnaissance metadata: the downpipe name and
// schedule, the source selectors and the crawl window live encrypted in the shard
// preamble (SPEC.md 5.3, 6.1). Only the opaque downpipeId appears here. A detached
// hybrid signature in root.manifest.json.sig covers its canonical bytes, verified
// against an operator-pinned signer (SPEC.md 5, 8).
type RootManifest struct {
	FormatVersion         string        `json:"formatVersion"`
	RunID                 string        `json:"runId"`
	CreatedAt             string        `json:"createdAt"`
	DownpipeID            string        `json:"downpipeId"`
	Envelope              Envelope      `json:"envelope"`
	Recipients            []Recipient   `json:"recipients"`
	MasterCapsule         []CapsuleWrap `json:"masterCapsule"`
	RecipientSetHash      string        `json:"recipientSetHash"`
	KeyCommitment         string        `json:"keyCommitment"`
	BreakGlassPresent     bool          `json:"breakGlassPresent"`
	Shards                []ShardRef    `json:"shards"`
	ShardCount            int           `json:"shardCount"`
	DeclaredRecordCount   int64         `json:"declaredRecordCount"`
	MerkleRoot            string        `json:"merkleRoot"`
	Freshness             Freshness     `json:"freshness"`
	SigningKeyFingerprint string        `json:"signingKeyFingerprint"`
}

// Freshness binds a run into the signed RUNLOG chain (SPEC.md 10). PrevRunID is the
// JSON null literal for a downpipe's first run.
type Freshness struct {
	PrevRunID   *string `json:"prevRunId"`
	RunlogIndex int64   `json:"runlogIndex"`
}

// Window is the crawl window of a run (SPEC.md 10), RFC 3339 UTC with milliseconds. It
// lives in the encrypted shard preamble, not the cleartext root.
type Window struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

// Source records one backed-up source and the selector that scoped it (SPEC.md 12.1).
type Source struct {
	Type        string   `json:"type"`
	NamespaceID string   `json:"namespaceId,omitempty"`
	Bucket      string   `json:"bucket,omitempty"`
	Label       string   `json:"label,omitempty"`
	Include     []string `json:"include,omitempty"`
	Exclude     []string `json:"exclude,omitempty"`
}

// Envelope names the pinned algorithm suite for the run (SPEC.md 4).
type Envelope struct {
	AEAD      string `json:"aead"`
	KEM       string `json:"kem"`
	Signature string `json:"sig"`
	KDF       string `json:"kdf"`
	ChunkSize int    `json:"chunkSize"`
	Codec     string `json:"codec"`
}

// Recipient lists a run's recipient public key material so the reader can compute the
// recipient-set hash and confirm the break-glass recipient is present. The private
// halves are not here; the break-glass private key is held offline (SPEC.md 7.6).
type Recipient struct {
	Fingerprint string `json:"fingerprint"`
	Role        string `json:"role"`
	X25519      string `json:"x25519"`
	MLKEM       string `json:"mlkem"`
}

// CapsuleWrap is one recipient's KEM-DEM wrap of the run master (SPEC.md 5.4), the
// JSON form of crypto.WrappedKey with binary fields base64url-encoded.
type CapsuleWrap struct {
	Fingerprint   string `json:"fingerprint"`
	KEMCiphertext string `json:"kemCiphertext"`
	Sealed        string `json:"sealed"`
}

// ShardRef points the reader at one encrypted shard manifest and binds its stored
// bytes by hash into the signed root (SPEC.md 5, 6).
type ShardRef struct {
	ID     string `json:"id"`
	Object string `json:"object"`
	SHA384 string `json:"sha384"`
}

// ShardPreamble is the first NDJSON line of an encrypted shard manifest (SPEC.md 6.1):
// a kind-tagged header carrying the reconnaissance metadata kept out of the cleartext
// root (the downpipe name and schedule, the source selectors, the crawl window) plus
// the per-shard record count. It is sealed with the records under the manifest subkey.
type ShardPreamble struct {
	Kind               string           `json:"kind"`
	FormatVersion      string           `json:"formatVersion"`
	RunID              string           `json:"runId"`
	ShardID            string           `json:"shardId"`
	ManifestCodec      string           `json:"manifestCodec"`
	Downpipe           PreambleDownpipe `json:"downpipe"`
	Source             Source           `json:"source"`
	Window             Window           `json:"window"`
	Consistency        string           `json:"consistency"`
	RecordCountInShard int64            `json:"recordCountInShard"`
}

// PreambleDownpipe is the human downpipe name and schedule, kept encrypted (SPEC.md 6.1).
type PreambleDownpipe struct {
	Name    string `json:"name"`
	Cadence string `json:"cadence"`
}

// ShardRecord is one line of an encrypted shard manifest: the metadata for one
// backed-up record, never its value (SPEC.md 6.2). The value lives only in the
// segments. The whole shard manifest is sealed under the manifest subkey, so these
// fields are confidential at rest.
type ShardRecord struct {
	Kind          string             `json:"kind"`
	SourceType    string             `json:"sourceType"`
	Namespace     string             `json:"namespace,omitempty"`
	Bucket        string             `json:"bucket,omitempty"`
	Database      string             `json:"database,omitempty"`
	Account       string             `json:"account,omitempty"`
	Name          string             `json:"name"`
	KeyNameHash   string             `json:"keyNameHash"`
	RecordID      string             `json:"recordId"`
	PlaintextSize int64              `json:"plaintextSize"`
	PlaintextSHA  string             `json:"plaintextSha384"`
	RecordHash    string             `json:"recordHash"`
	Codec         string             `json:"codec"`
	Segments      []Segment          `json:"segments"`
	RecordSalt    string             `json:"recordSalt,omitempty"`
	KV            *KVDescriptor      `json:"kv,omitempty"`
	R2            *R2Descriptor      `json:"r2,omitempty"`
	Secrets       *SecretsDescriptor `json:"secrets,omitempty"`
	D1            *D1Descriptor      `json:"d1,omitempty"`
	// IncompleteMarker, when non-empty, stamps this record as an INCOMPLETENESS MARKER
	// rather than real backed-up data: the source was only partially available when the run
	// was written, so the record's value is a sentinel JSON placeholder and NOT the
	// source's live content. Its string is the marker kind, one of the closed six-member
	// set the writer stamps: _truncated, _unavailable, _skipped, _pending, _refused,
	// _vanished (schema.json pins the same enum). The field is OPTIONAL and backward-compatible:
	// it is absent on every normal record and on every archive sealed before the engine
	// emitted it, decoding to "" so the record is treated as normal (OpenShard uses a plain
	// json.Unmarshal, so an absent field never breaks decoding an existing archive). Like
	// every other record field it is sealed inside the shard manifest, whose SHA-384 the
	// signed root binds, so it is tamper-evident. It is NOT one of the SPEC.md 6.5 record-hash
	// inputs (RecordHashOf covers only recordId, plaintextSha384, keyNameHash and
	// plaintextSize), so adding it changes neither the recomputed Merkle root nor the
	// verification of any archive that lacks it.
	IncompleteMarker string `json:"incompleteMarker,omitempty"`
}

// The per-source descriptors carry the configuration a restore reconstructs beyond the
// value bytes (SPEC.md 6.2, 12.3). Opaque metadata is held as raw JSON so the reader
// never interprets it; it only restores it.

// KVDescriptor is a Workers KV record's metadata and expiration.
type KVDescriptor struct {
	Metadata   json.RawMessage `json:"metadata,omitempty"`
	Expiration int64           `json:"expiration,omitempty"`
}

// R2Descriptor is an R2 object's HTTP and custom metadata.
type R2Descriptor struct {
	HTTPMetadata   json.RawMessage `json:"httpMetadata,omitempty"`
	CustomMetadata json.RawMessage `json:"customMetadata,omitempty"`
}

// SecretsDescriptor reconstructs a secret's wiring on restore (SPEC.md 12.3): the
// store, the scope, an optional comment, and for a per-Worker secret the Worker and
// the binding variable. The value itself is never here; it lives only in the segment.
type SecretsDescriptor struct {
	Store      string `json:"store,omitempty"`
	Scope      string `json:"scope,omitempty"`
	Comment    string `json:"comment,omitempty"`
	Worker     string `json:"worker,omitempty"`
	BindingVar string `json:"bindingVar,omitempty"`
}

// D1Descriptor records how a D1 database dump was produced so a restore can replay it.
type D1Descriptor struct {
	Format string `json:"format,omitempty"`
}

// Segment names one .seg object and the chunk range of this record within it (SPEC.md
// 6.2, 7.8). A record is one or more segments in order; a packed record is a byte
// slice of a shared segment. ChunkRange is [first, lastExclusive) over the STREAM
// chunk index; Packed is nil for a whole-segment entry and otherwise gives the
// record's byte offset and length within the decrypted concatenation.
type Segment struct {
	Object     string  `json:"object"`
	ChunkRange [2]int  `json:"chunkRange"`
	Packed     *Packed `json:"packed"`
}

// Packed is a record's byte slice within a shared packed segment (SPEC.md 6.2).
type Packed struct {
	Offset int64 `json:"offset"`
	Length int64 `json:"length"`
}

// RunlogEntry is one line of the signed _RECOVERY/RUNLOG freshness anchor (SPEC.md
// 10): an append-only, index-monotonic log chaining each downpipe's runs through
// prevRunId, so a reader can detect a rolled-back or withheld run. PrevRunID is the
// JSON null literal for a downpipe's first run; Status is "active" or "superseded".
type RunlogEntry struct {
	Index       int64   `json:"index"`
	RunID       string  `json:"runId"`
	DownpipeID  string  `json:"downpipeId"`
	Time        string  `json:"time"`
	RecordCount int64   `json:"recordCount"`
	PrevRunID   *string `json:"prevRunId"`
	Status      string  `json:"status"`
}
