package source

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// This file is the streamed-read side of both backends: GetReader opens one object as
// a bounded stream so a large sealed segment decrypts chunk by chunk without its
// ciphertext ever being buffered. The buffered Get paths are untouched (small objects
// keep their tight whole-request bounds); GetReader applies the same hardening with
// the byte ceiling enforced ON the stream.

// boundedReadCloser enforces the per-object byte ceiling on a streamed read: the hard
// guard equivalent of the buffered path's LimitReader-plus-length check, delivered as
// an explicit error instead of a silent truncation.
type boundedReadCloser struct {
	prefix string // error verb, matching the backend's buffered wording
	key    string
	src    io.Reader
	closer io.Closer
	limit  int64
	n      int64
}

func (b *boundedReadCloser) Read(p []byte) (int, error) {
	n, err := b.src.Read(p)
	b.n += int64(n)
	if b.n > b.limit {
		return n, fmt.Errorf("%s %s: object exceeds the %d-byte limit", b.prefix, b.key, b.limit)
	}
	return n, err
}

func (b *boundedReadCloser) Close() error { return b.closer.Close() }

// GetReader opens the object at key as a stream, with the same hardening as Get: the
// key is cleaned and rooted, a symlink final component is refused, the size check runs
// on the open descriptor (never the path), and the byte ceiling is enforced on the
// stream, so a file that outgrows its fd-stat mid-read aborts with an error rather
// than being consumed. The int64 is the fd-stat size hint (negative when unknown).
// The context is accepted for interface parity; a local read has no waiting to cancel.
func (d *DirStore) GetReader(_ context.Context, key string) (io.ReadCloser, int64, error) {
	rel := filepath.Clean("/" + filepath.FromSlash(key))
	p := filepath.Join(d.baseDir, rel)

	if li, err := os.Lstat(p); err == nil && li.Mode()&os.ModeSymlink != 0 {
		return nil, 0, fmt.Errorf("read object %s: refusing to follow a symlink", key)
	}

	fh, err := os.Open(p)
	if err != nil {
		return nil, 0, fmt.Errorf("read object %s: %w", key, err)
	}
	limit := d.limit()
	size := int64(-1)
	if fi, err := fh.Stat(); err == nil {
		if !fi.Mode().IsRegular() {
			_ = fh.Close()
			return nil, 0, fmt.Errorf("read object %s: not a regular file", key)
		}
		if fi.Size() > limit {
			_ = fh.Close()
			return nil, 0, fmt.Errorf("read object %s: %d bytes exceeds the %d-byte limit", key, fi.Size(), limit)
		}
		size = fi.Size()
	}
	return &boundedReadCloser{prefix: "read object", key: key, src: fh, closer: fh, limit: limit}, size, nil
}

// GetContext is DirStore's Get with an up-front context check. A local disk read never
// blocks long enough to need mid-read cancellation; the capability exists so a torn-down
// walk skips queued reads immediately.
func (d *DirStore) GetContext(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("read object %s: %w", key, err)
	}
	return d.Get(key)
}

// idleWatchdogBody aborts a streamed response body that stalls: every Read re-arms a
// timer, and if no read completes within the idle bound the request context is
// cancelled, failing the in-flight read. The timeout is reported as its own error so
// the operator sees "stalled stream", not a bare context cancellation.
type idleWatchdogBody struct {
	key      string
	idle     time.Duration
	body     io.ReadCloser
	timer    *time.Timer
	cancel   context.CancelFunc
	timedOut atomic.Bool
}

func (w *idleWatchdogBody) Read(p []byte) (int, error) {
	w.timer.Reset(w.idle)
	n, err := w.body.Read(p)
	if err != nil && w.timedOut.Load() {
		return n, fmt.Errorf("get %s: no bytes for %s, aborting the stalled stream", w.key, w.idle)
	}
	return n, err
}

func (w *idleWatchdogBody) Close() error {
	w.timer.Stop()
	w.cancel()
	return w.body.Close()
}

// GetReader fetches the object as a stream. The buffered Get keeps its 60 s
// whole-request client (right for small manifest objects); the streamed path instead
// bounds each PHASE: connect, TLS and first byte through the shared transport, and the
// body through an idle watchdog that aborts the request when no bytes arrive for the
// store's idle bound, so a large object may stream for minutes while a stalled body
// still dies quickly. Redirects are refused identically, the status and Content-Length
// gates match Get, and the per-object byte ceiling is enforced on the stream.
func (s *S3Store) GetReader(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	req, err := s.signedGetRequest(key)
	if err != nil {
		return nil, 0, err
	}
	wctx, cancel := context.WithCancel(ctx)
	req = req.WithContext(wctx)
	resp, err := s.streamClient.Do(req)
	if err != nil {
		cancel()
		return nil, 0, &unreachableErr{err: fmt.Errorf("get %s: could not reach the destination: %w", key, s.sentTo(key, err))}
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		cancel()
		return nil, 0, &unreachableErr{err: fmt.Errorf("get %s: %s returned status %d%s", key, s.objectAddress(key), resp.StatusCode, httpStatusHint(resp.StatusCode))}
	}
	if resp.ContentLength > maxObjectBytes {
		_ = resp.Body.Close()
		cancel()
		return nil, 0, fmt.Errorf("get %s: %d bytes exceeds the %d-byte limit", key, resp.ContentLength, maxObjectBytes)
	}
	w := &idleWatchdogBody{key: key, idle: s.idleTimeout, body: resp.Body, cancel: cancel}
	w.timer = time.AfterFunc(s.idleTimeout, func() {
		w.timedOut.Store(true)
		cancel()
	})
	return &boundedReadCloser{prefix: "get", key: key, src: w, closer: w, limit: maxObjectBytes}, resp.ContentLength, nil
}
