// Package restore plans and applies an offline recovery of a downpipe run into a
// target the operator controls. It runs entirely on the operator's machine with the
// customer-held break-glass private key; neither Cloudflare nor the vendor is in the
// loop and nothing about the recovery leaves the machine.
//
// The flow is two phase. Plan enumerates the target's existing state and diffs the
// run's records against it to produce a no-clobber Plan: which records would be
// written, how many bytes, and which records conflict with state already present in
// the target. Plan never writes and never decrypts a value, so a dry run is cheap and
// side-effect free; the planned byte counts come from the signed manifest. Apply then
// reassembles and hash-verifies each non-conflicting record through the format reader
// (which decrypts with the break-glass identity) and writes it, reporting restored
// versus failed honestly so a single per-record failure never silently aborts the run
// or masquerades as success.
//
// No-custody. A Plan and a Result carry only counts, names, sizes and enums. The
// names are the customer's own record names going to the customer's own sink, which is
// their data to their own target. They never carry a key, a secret value, a recipient
// fingerprint or any other key-derived material.
//
// D1. A D1 database is not replayed live offline; its records are opaque bytes written
// to files for the operator to replay against a fresh database. A large database backs
// up as a SEQUENCE of records per database -- one "<db>/00-header" (the table DDL), many
// "<db>/10-rows/<table>/<page>" (one keyset page of rows each), then one "<db>/20-schema"
// (indexes, triggers, views) -- so the file sink writes one file per record. Their names
// sort header -> rows -> schema, which is the order the operator replays them in to
// rebuild the database (create the tables, insert the rows, then build the schema). A
// database backed up before resumability is a single record named for the database and
// restores as one file unchanged.
//
// The normative format and the restore receipt live in docs/format/SPEC.md
// (sections 8.5, 12.6).
package restore
