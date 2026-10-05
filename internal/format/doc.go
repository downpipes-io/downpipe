// Package format reads and verifies downpipe archives. It parses the root and
// shard manifests and resolves content-addressed segments to verified
// plaintext, checking completeness against the signed declared count.
//
// The normative format lives in docs/format/SPEC.md.
package format
