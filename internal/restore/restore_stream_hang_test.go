package restore

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// earlyReturnStreamTarget is a StreamTarget whose WriteStream returns an error WITHOUT
// reading a single byte from src, mimicking the most reachable real trigger: the DirTarget
// O_EXCL no-clobber reservation rejecting a destination that appeared in the TOCTOU window
// between MakePlan and the write, so WriteStream returns before draining the stream. It is
// the minimal reproduction for downpipe-src-005-M1: on the streaming path applyStream
// bridges the reader to the target with an io.Pipe, and a target that returns before
// reading leaves the reader's pw.Write with no reader, so without the fix the apply hangs
// forever at the receive on the done channel.
type earlyReturnStreamTarget struct {
	existing map[string]struct{}
	reason   error // returned from WriteStream without consuming src
	written  map[string][]byte
}

func newEarlyReturnStreamTarget(reason error, existing ...string) *earlyReturnStreamTarget {
	t := &earlyReturnStreamTarget{
		existing: map[string]struct{}{},
		reason:   reason,
		written:  map[string][]byte{},
	}
	for _, k := range existing {
		t.existing[k] = struct{}{}
	}
	return t
}

func (t *earlyReturnStreamTarget) Kind() string                    { return "fake" }
func (t *earlyReturnStreamTarget) Key(name string) (string, error) { return name, nil }

func (t *earlyReturnStreamTarget) Existing() (map[string]struct{}, error) {
	out := make(map[string]struct{}, len(t.existing))
	for k := range t.existing {
		out[k] = struct{}{}
	}
	return out, nil
}

func (t *earlyReturnStreamTarget) Write(key string, value []byte) error {
	cp := make([]byte, len(value))
	copy(cp, value)
	t.written[key] = cp
	return nil
}

func (t *earlyReturnStreamTarget) Close() error { return nil }

// WriteStream returns reason immediately, never reading src. This is exactly the shape of
// DirTarget.WriteStream's no-clobber early return (the O_EXCL placeholder open failing
// before any io.Copy of src), which is the documented hang trigger.
func (t *earlyReturnStreamTarget) WriteStream(_ string, _ io.Reader, _ int64) error {
	return t.reason
}

// runApplyWithin runs Apply in a goroutine and waits up to d for it to complete. It returns
// the result and true if Apply finished, or a zero result and false on timeout. The timeout
// is essential because the pre-fix code HANGS at the receive on the done channel, so a red
// run must manifest as a timeout rather than wedging the test binary indefinitely.
func runApplyWithin(t *testing.T, r recordReader, target Target, d time.Duration) (*Result, bool) {
	t.Helper()
	type outcome struct {
		res *Result
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		_, res, err := Apply(r, target, true)
		ch <- outcome{res: res, err: err}
	}()
	select {
	case o := <-ch:
		if o.err != nil {
			t.Fatalf("Apply returned an unexpected top-level error: %v", o.err)
		}
		return o.res, true
	case <-time.After(d):
		return nil, false
	}
}

// TestApplyStreamingEarlyReturnDoesNotHang is the primary red-before-green guard for
// downpipe-src-005-M1. A streamable record whose target WriteStream returns before reading
// (a no-clobber rejection of a key that appeared after planning) must NOT hang the apply: it
// must complete within the timeout, the record must be recorded as a RecordFailure carrying
// the target's reason, and the bridging goroutine must not be leaked.
func TestApplyStreamingEarlyReturnDoesNotHang(t *testing.T) {
	r := newStreamingReader([2]string{"a", "alpha"})
	noClobber := fmt.Errorf("write a (it may already exist): file exists")
	target := newEarlyReturnStreamTarget(noClobber)

	before := runtime.NumGoroutine()
	res, finished := runApplyWithin(t, r, target, 5*time.Second)
	if !finished {
		t.Fatal("Apply hung on the streaming path when WriteStream returned before reading (downpipe-src-005-M1)")
	}
	if res.Restored != 0 {
		t.Fatalf("a record whose WriteStream rejected it must not count as restored, got %d", res.Restored)
	}
	if len(res.Failed) != 1 || res.Failed[0].Name != "a" {
		t.Fatalf("expected exactly one failure for 'a', got %+v", res.Failed)
	}
	// The recorded reason must be the TARGET's reason (the no-clobber reason), not the
	// closed-pipe teardown noise the fix induces to unblock the goroutine.
	if got := res.Failed[0].Reason; got != noClobber.Error() {
		t.Fatalf("failure reason must be the target's reason, got %q want %q", got, noClobber.Error())
	}

	// No goroutine leak: the bridging goroutine must have finished. Allow a short settle for
	// the just-finished goroutine to be reaped.
	assertNoGoroutineLeak(t, before)
}

// TestApplyStreamingNoClobberDirTargetDoesNotHang exercises the real DirTarget no-clobber
// path end to end: a file that appears at the destination after planning (here, planted
// directly so MakePlan sees a clean dir but WriteStream's O_EXCL reservation fails). The
// apply must complete within the timeout rather than hang.
func TestApplyStreamingNoClobberDirTargetDoesNotHang(t *testing.T) {
	dir := t.TempDir()
	r := newStreamingReader([2]string{"a", "alpha"})

	// Plan against an empty target so "a" is a planned write, then plant the destination file
	// so WriteStream's O_EXCL reservation rejects it (the TOCTOU window the finding describes).
	target := &planThenClobberTarget{DirTarget: NewDirTarget(dir), dir: dir, plant: "a"}

	before := runtime.NumGoroutine()
	res, finished := runApplyWithin(t, r, target, 5*time.Second)
	if !finished {
		t.Fatal("Apply hung on the real DirTarget no-clobber streaming path (downpipe-src-005-M1)")
	}
	if res.Restored != 0 || len(res.Failed) != 1 || res.Failed[0].Name != "a" {
		t.Fatalf("expected one no-clobber failure for 'a', got restored=%d failed=%+v", res.Restored, res.Failed)
	}
	// The planted file must be untouched: the no-clobber guard held.
	got, err := os.ReadFile(filepath.Join(dir, "a"))
	if err != nil || string(got) != "PLANTED" {
		t.Fatalf("no-clobber violated: file a is now %q (err=%v)", got, err)
	}
	assertNoGoroutineLeak(t, before)
}

// planThenClobberTarget plants a file at the destination key after Existing() is read by
// MakePlan, so the plan sees a clean directory and WriteStream's O_EXCL reservation then
// rejects the now-present file. It exposes the exact TOCTOU window described in the finding.
type planThenClobberTarget struct {
	*DirTarget
	dir   string
	plant string
}

func (p *planThenClobberTarget) Existing() (map[string]struct{}, error) {
	out, err := p.DirTarget.Existing()
	if err != nil {
		return nil, err
	}
	// After the plan reads the (empty) target state, plant the destination file so the write
	// hits the O_EXCL rejection. WriteStream then returns before reading the stream.
	if werr := os.WriteFile(filepath.Join(p.dir, p.plant), []byte("PLANTED"), 0o600); werr != nil {
		return nil, werr
	}
	return out, nil
}

// TestApplyStreamingTamperedPrecedencePreserved guards error precedence after the fix: a
// genuinely tampered/truncated streamable record (RestoreRecordTo writes the bytes then
// returns a bad-SHA error) must STILL surface as the integrity failure, never as the
// closed-pipe teardown noise the fix uses to unblock the goroutine.
func TestApplyStreamingTamperedPrecedencePreserved(t *testing.T) {
	dir := t.TempDir()
	r := newStreamingReader([2]string{"bad", "corrupt"})
	r.failAfter["bad"] = true
	target := NewDirTarget(dir)

	res, finished := runApplyWithin(t, r, target, 5*time.Second)
	if !finished {
		t.Fatal("Apply hung on a tampered streamable record")
	}
	if len(res.Failed) != 1 || res.Failed[0].Name != "bad" {
		t.Fatalf("expected one failure for 'bad', got %+v", res.Failed)
	}
	reason := res.Failed[0].Reason
	if !containsHashCheck(reason) {
		t.Fatalf("tampered record must surface its integrity reason, got %q", reason)
	}
	if containsClosedPipe(reason) {
		t.Fatalf("integrity reason was masked by closed-pipe teardown noise: %q", reason)
	}
}

// TestApplyStreamingSuccessAfterFix confirms the normal streaming path still restores the
// right byte count after the fix (no regression).
func TestApplyStreamingSuccessAfterFix(t *testing.T) {
	dir := t.TempDir()
	r := newStreamingReader([2]string{"a", "alpha"}, [2]string{"b", "bravo-payload"})
	target := NewDirTarget(dir)

	res, finished := runApplyWithin(t, r, target, 5*time.Second)
	if !finished {
		t.Fatal("Apply hung on a clean streaming restore")
	}
	if !res.OK() || res.Restored != 2 {
		t.Fatalf("expected 2 clean restores, got restored=%d failed=%+v", res.Restored, res.Failed)
	}
	if res.BytesRestored != int64(len("alpha")+len("bravo-payload")) {
		t.Fatalf("byte total wrong after fix: %d", res.BytesRestored)
	}
}

func assertNoGoroutineLeak(t *testing.T, before int) {
	t.Helper()
	// Allow a short settle for the just-completed bridging goroutine to be reaped before
	// sampling, then assert we have not grown the goroutine count.
	deadline := time.Now().Add(2 * time.Second)
	for {
		runtime.Gosched()
		after := runtime.NumGoroutine()
		if after <= before {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine leak: before=%d after=%d (the pipe bridge goroutine was not reaped)", before, after)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func containsHashCheck(s string) bool { return contains(s, "plaintext hash check") }
func containsClosedPipe(s string) bool {
	return contains(s, "closed pipe") || contains(s, io.ErrClosedPipe.Error())
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// compile-time guard that the stubs satisfy the interfaces the streaming path requires.
var (
	_ Target          = (*earlyReturnStreamTarget)(nil)
	_ StreamTarget    = (*earlyReturnStreamTarget)(nil)
	_ Target          = (*planThenClobberTarget)(nil)
	_ StreamTarget    = (*planThenClobberTarget)(nil)
	_ recordReader    = (*streamingFakeReader)(nil)
	_ streamingReader = (*streamingFakeReader)(nil)
)
