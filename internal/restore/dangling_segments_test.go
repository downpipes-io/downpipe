package restore

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/downpipes-io/downpipe/internal/format"
)

// TestDanglingSegmentsCountsDistinctAbsentPaths pins the counting rule at the unit, where
// the shapes that break it can be written down directly.
//
// The receipt's danglingSegments is a count of seg/ OBJECT PATHS, and segments are content
// addressed, so two records holding identical bytes name one object. Counting failed records
// would report two dangling references where the bucket is missing one, and over-claiming is
// the exact failure mode this field was changed to stop.
func TestDanglingSegmentsCountsDistinctAbsentPaths(t *testing.T) {
	absent := func(object string) error {
		return &format.SegmentReadError{Object: object, Err: fmt.Errorf("read object %s: %w", object, fs.ErrNotExist)}
	}
	cases := []struct {
		name   string
		failed []RecordFailure
		want   int64
	}{
		{"no failures at all", nil, 0},
		{
			name:   "one record, one absent segment",
			failed: []RecordFailure{{Name: "a", Err: absent("seg/aa/aaaa.seg")}},
			want:   1,
		},
		{
			name: "two records sharing ONE absent segment count once",
			failed: []RecordFailure{
				{Name: "a", Err: absent("seg/aa/aaaa.seg")},
				{Name: "b", Err: absent("seg/aa/aaaa.seg")},
			},
			want: 1,
		},
		{
			name: "two records, two different absent segments count twice",
			failed: []RecordFailure{
				{Name: "a", Err: absent("seg/aa/aaaa.seg")},
				{Name: "b", Err: absent("seg/bb/bbbb.seg")},
			},
			want: 2,
		},
		{
			name: "a segment that was PRESENT and failed its check is not dangling",
			failed: []RecordFailure{
				{Name: "a", Err: fmt.Errorf("record a failed its plaintext hash check")},
			},
			want: 0,
		},
		{
			name: "an absent object that is not a segment read is not counted",
			failed: []RecordFailure{
				{Name: "a", Err: fmt.Errorf("read shard s0: %w", fs.ErrNotExist)},
			},
			want: 0,
		},
		{
			// Dropping the fs.ErrNotExist half of the predicate would leave every case above
			// green, because every fixture that carried a SegmentReadError also carried
			// fs.ErrNotExist. A segment GET that was refused rather than answered is a read
			// this reader could not complete, not an object that is gone, and counting it
			// here would send an operator to fetch a copy of an object that is sitting
			// where it should be.
			name: "a segment fetch refused rather than answered is not a dangling reference",
			failed: []RecordFailure{
				{Name: "a", Err: &format.SegmentReadError{Object: "seg/aa/aaaa.seg", Err: fmt.Errorf("read object seg/aa/aaaa.seg: %w", fs.ErrPermission)}},
			},
			want: 0,
		},
		{
			name: "a mixture reports only the distinct absent segments",
			failed: []RecordFailure{
				{Name: "a", Err: absent("seg/aa/aaaa.seg")},
				{Name: "b", Err: absent("seg/aa/aaaa.seg")},
				{Name: "c", Err: absent("seg/cc/cccc.seg")},
				{Name: "d", Err: fmt.Errorf("record d failed its plaintext hash check")},
			},
			want: 2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := &Result{Failed: tc.failed}
			if got := res.DanglingSegments(); got != tc.want {
				t.Errorf("DanglingSegments() = %d, want %d", got, tc.want)
			}
			// AnyAbsentObject is the older, coarser question over the same field, and the
			// two must agree on direction: a non-zero dangling count means at least one
			// object was absent. It is a control on the fixtures as much as on the code,
			// because a fixture whose errors did not actually wrap fs.ErrNotExist would
			// make every "want 0" case pass for the wrong reason.
			if tc.want > 0 && !res.AnyAbsentObject() {
				t.Errorf("fixture control: %d dangling segments but AnyAbsentObject() is false", tc.want)
			}
		})
	}
}

// TestSegmentReadErrorPreservesTextAndChain: the typed error was introduced to carry the
// object path, not to change what an operator reads or what errors.Is answers. A change to
// either would be a silent behaviour change riding along with a counting fix.
func TestSegmentReadErrorPreservesTextAndChain(t *testing.T) {
	inner := fmt.Errorf("read object seg/aa/aaaa.seg: %w", fs.ErrNotExist)
	typed := &format.SegmentReadError{Object: "seg/aa/aaaa.seg", Err: inner}
	plain := fmt.Errorf("read segment %s: %w", "seg/aa/aaaa.seg", inner)
	if typed.Error() != plain.Error() {
		t.Errorf("the typed error must read exactly as the fmt.Errorf it replaced:\n got: %s\nwant: %s", typed, plain)
	}
	if !errors.Is(typed, fs.ErrNotExist) {
		t.Error("the typed error must still unwrap to fs.ErrNotExist, or every absence check downstream goes quiet")
	}
	if typed.Object != "seg/aa/aaaa.seg" {
		t.Errorf("Object = %q, want the seg/ path the manifest named", typed.Object)
	}
}

// TestDanglingOnlyIsFalseWheneverAnythingFailedACheck pins the verdict question, which is
// narrower than the counting one above and narrower than AnyAbsentObject.
//
// It decides an exit status and a customer-facing sentence, and getting it wrong in the
// permissive direction is the damaging error: a pass holding one altered record would be
// announced as merely incomplete, and the operator would go looking for a copy of an object
// instead of treating bytes they already hold as untrusted. So anything that is not provably
// an absent seg/ object turns it off, including an absent object this code cannot name as a
// segment.
func TestDanglingOnlyIsFalseWheneverAnythingFailedACheck(t *testing.T) {
	absent := func(object string) error {
		return &format.SegmentReadError{Object: object, Err: fmt.Errorf("read object %s: %w", object, fs.ErrNotExist)}
	}
	cases := []struct {
		name   string
		failed []RecordFailure
		want   bool
	}{
		{"no failures at all is complete, not incomplete", nil, false},
		{"one absent segment", []RecordFailure{{Name: "a", Err: absent("seg/aa/aaaa.seg")}}, true},
		{
			name: "two records sharing one absent segment",
			failed: []RecordFailure{
				{Name: "a", Err: absent("seg/aa/aaaa.seg")},
				{Name: "b", Err: absent("seg/aa/aaaa.seg")},
			},
			want: true,
		},
		{
			name: "one absent segment beside one failed check",
			failed: []RecordFailure{
				{Name: "a", Err: absent("seg/aa/aaaa.seg")},
				{Name: "b", Err: fmt.Errorf("chunk 0 authentication failed")},
			},
			want: false,
		},
		{
			name:   "a segment that was present and failed its check",
			failed: []RecordFailure{{Name: "a", Err: fmt.Errorf("record a failed its plaintext hash check")}},
			want:   false,
		},
		{
			name:   "an absent object this code cannot name as a segment",
			failed: []RecordFailure{{Name: "a", Err: fmt.Errorf("read shard s0: %w", fs.ErrNotExist)}},
			want:   false,
		},
		{
			// The other half of the predicate: a segment GET that was REFUSED rather than
			// answered. The object may well be there, so this is not an incompleteness
			// verdict and the harder reading has to stand.
			name:   "a segment fetch refused rather than answered",
			failed: []RecordFailure{{Name: "a", Err: &format.SegmentReadError{Object: "seg/aa/aaaa.seg", Err: fmt.Errorf("read object seg/aa/aaaa.seg: %w", fs.ErrPermission)}}},
			want:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := &Result{Failed: tc.failed}
			if got := res.DanglingOnly(); got != tc.want {
				t.Errorf("DanglingOnly() = %v, want %v", got, tc.want)
			}
			// The verdict and the count are answers to one question and are read off one
			// predicate, so a true verdict must always be backed by a countable object. A
			// verdict that outran its own evidence is what put "1 of 1 record(s) failed
			// integrity" over an archive that had failed nothing.
			if tc.want && res.DanglingSegments() == 0 {
				t.Error("DanglingOnly() is true while DanglingSegments() counts nothing, so the printed line would name no object for the operator to go and fetch")
			}
		})
	}
}
