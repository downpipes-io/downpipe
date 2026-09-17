## What this changes

A short description of the change and why.

## Checklist

- [ ] `make build test vet` passes (`go test -race ./...`), and `gofmt -s -w .` leaves no diff.
- [ ] New behaviour is covered by a test; reader changes are covered by a conformance vector where they touch the format.
- [ ] No change to a byte-level rule of the `downpipe/0.1.0` archive format (if there is one, it is a new format major version with a SPEC.md update and new vectors, raised as a separate discussion first).
- [ ] The recovery/reader path (keygen, inspect, verify, attest, restore, selftest) still makes no network call.
- [ ] Docs updated (README / SPEC / CONFORMANCE / CHANGELOG) where relevant.

## Notes for reviewers
