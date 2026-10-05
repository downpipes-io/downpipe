package restore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/downpipes-io/downpipe/internal/spec"
)

// MetadataSidecarSuffix is appended to a restored record's destination key to name the file
// that holds the record's source metadata on the file sink (SPEC.md 6.3). The record
// "img/logo.png" is restored to img/logo.png and its metadata to img/logo.png.downpipe-meta.json.
const MetadataSidecarSuffix = ".downpipe-meta.json"

// MetadataSidecarFormat is the value of the sidecar's "format" field. A reader of the sidecar
// checks it before it trusts the shape. A change to the shape changes the label.
const MetadataSidecarFormat = "downpipe-restore-metadata/1"

// MetadataTarget is an optional capability of a Target that can keep a record's source
// metadata (the kv and r2 descriptors of SPEC.md 6.2) next to the value it wrote. The file
// sink implements it with a sidecar file. A target that does not implement it cannot keep the
// metadata, and the apply lists each such record in Result.MetadataUnapplied so the loss is
// never silent.
type MetadataTarget interface {
	// MetadataKey returns the destination key of the metadata for the value at key. It is a
	// pure function of key, so the planner can claim it and catch a record that maps to it.
	MetadataKey(key string) string
	// WriteMetadata writes doc under MetadataKey(key). It MUST refuse to overwrite an
	// existing key, with the same no-clobber contract as Target.Write.
	WriteMetadata(key string, doc []byte) error
}

// RecordMetadataUnapplied is one restored record whose value was written but whose source
// metadata the target could not keep. It names the record, the key, the source type, the
// descriptor fields the record carried and the reason. It never carries a metadata value.
type RecordMetadataUnapplied struct {
	Name       string
	Key        string
	SourceType string
	Fields     []string
	Reason     string
}

// metadataSidecar is the documented sidecar shape (SPEC.md 6.3). The coordinates repeat the
// record line so a re-upload can put the object back under its source-native name, which the
// file path cannot always carry (safeKey drops empty, "." and ".." elements). The descriptor
// objects are the record line's own, with the opaque metadata carried unchanged.
type metadataSidecar struct {
	Format       string             `json:"format"`
	SourceType   string             `json:"sourceType"`
	Namespace    string             `json:"namespace,omitempty"`
	Bucket       string             `json:"bucket,omitempty"`
	Name         string             `json:"name"`
	PlaintextSHA string             `json:"plaintextSha384"`
	KV           *spec.KVDescriptor `json:"kv,omitempty"`
	R2           *spec.R2Descriptor `json:"r2,omitempty"`
}

// metadataFields names the kv and r2 descriptor fields a record carries, in a fixed order. An
// empty result means the record has no metadata to keep. It reads the same omitempty rules
// the writer applies (SPEC.md 6.2), so a descriptor object with no set field counts as none.
func metadataFields(rec spec.ShardRecord) []string {
	var out []string
	if rec.KV != nil {
		if len(rec.KV.Metadata) > 0 {
			out = append(out, "kv.metadata")
		}
		if rec.KV.Expiration != 0 {
			out = append(out, "kv.expiration")
		}
	}
	if rec.R2 != nil {
		if len(rec.R2.HTTPMetadata) > 0 {
			out = append(out, "r2.httpMetadata")
		}
		if len(rec.R2.CustomMetadata) > 0 {
			out = append(out, "r2.customMetadata")
		}
	}
	return out
}

// encodeMetadataSidecar renders the sidecar for rec. HTML escaping is off, so a value such as
// a Content-Disposition with "&" or "<" keeps its bytes. encoding/json compacts the opaque
// metadata but never changes a value inside it.
func encodeMetadataSidecar(rec spec.ShardRecord) ([]byte, error) {
	doc := metadataSidecar{
		Format: MetadataSidecarFormat, SourceType: rec.SourceType,
		Namespace: rec.Namespace, Bucket: rec.Bucket, Name: rec.Name,
		PlaintextSHA: rec.PlaintextSHA, KV: rec.KV, R2: rec.R2,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("encode metadata for %s: %w", rec.RecordID, err)
	}
	return buf.Bytes(), nil
}

// claimMetadataKey adds the metadata key of a planned record to the within-run claimed set,
// so a later record whose own key is that path is a collision in the plan and not a write
// that fails at apply time. It claims nothing when the record has no metadata, when the
// target cannot keep metadata, or when the path is already taken; in the last case the
// sidecar write is refused at apply time and the record is listed in MetadataUnapplied.
func claimMetadataKey(t Target, rec spec.ShardRecord, key string, existing, claimed map[string]struct{}) {
	mt, ok := t.(MetadataTarget)
	if !ok || len(metadataFields(rec)) == 0 {
		return
	}
	mk := mt.MetadataKey(key)
	if _, taken := existing[mk]; taken {
		return
	}
	if _, taken := claimed[mk]; taken {
		return
	}
	claimed[mk] = struct{}{}
}

// applyMetadata keeps the source metadata of one record whose value was just written. On a
// MetadataTarget it writes the sidecar and counts it. On any other target, and on a sidecar
// write that fails, it lists the record in MetadataUnapplied. The value is already written
// and verified, so a metadata problem never turns the record into a failure. The discard sink
// writes nothing at all, so it has no metadata to lose and is skipped.
func (res *Result) applyMetadata(t Target, rec spec.ShardRecord, key string) {
	fields := metadataFields(rec)
	if len(fields) == 0 || t.Kind() == "discard" {
		return
	}
	mt, ok := t.(MetadataTarget)
	if !ok {
		res.noteMetadataUnapplied(rec, key, fields, fmt.Sprintf("the %s target has no place to keep metadata; restore with --sink file to keep it in a sidecar", t.Kind()))
		return
	}
	doc, err := encodeMetadataSidecar(rec)
	if err == nil {
		err = mt.WriteMetadata(key, doc)
	}
	if err != nil {
		res.noteMetadataUnapplied(rec, key, fields, err.Error())
		return
	}
	res.MetadataSidecars++
}

func (res *Result) noteMetadataUnapplied(rec spec.ShardRecord, key string, fields []string, reason string) {
	res.MetadataUnapplied = append(res.MetadataUnapplied, RecordMetadataUnapplied{
		Name: rec.Name, Key: key, SourceType: rec.SourceType, Fields: fields, Reason: reason,
	})
}

// sortMetadataUnapplied orders the list by name for a stable report, as the other lists are.
func (res *Result) sortMetadataUnapplied() {
	sort.Slice(res.MetadataUnapplied, func(i, j int) bool { return res.MetadataUnapplied[i].Name < res.MetadataUnapplied[j].Name })
}
