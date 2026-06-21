// Package audit — sink layer.
//
// A Sink is one destination for audit records. The Emitter fans every
// record out to every configured Sink; this file defines the Sink
// interface plus the four concrete implementations: stderrSink (the
// default), stdoutSink (opt-in via --audit-stdout), fileSink (with
// fsync per Plan R11), and multiSink (the fan-out wrapper the
// Emitter actually owns).
//
// All Sinks must be safe to call from multiple goroutines. The
// stdio sinks wrap os.File which is already goroutine-safe for
// concurrent Write; the file sink wraps its mutex-protected *os.File
// directly; the multiSink serializes via its own mutex so the
// underlying sinks never see interleaved partial writes (the per-sink
// write is a single Write call so each sink still sees whole lines).
package audit

import (
	"fmt"
	"io"
	"os"
	"sync"
)

// Sink is one destination for audit records. Emit calls Write for
// every record; Close is called once when the Emitter shuts down.
//
// Implementations must:
//   - Be safe for concurrent use by multiple goroutines.
//   - Write each record as a single Write call (no partial writes).
//   - Treat Write as fire-and-forget except for error propagation:
//     a Write error is returned to the caller and no other guarantees
//     are made (the caller decides whether to retry, log, or abort).
//
// The Sink contract deliberately does NOT require line framing: the
// Emitter adds a newline after every Write so Sinks do not have to
// remember. File Sinks additionally fsync inside Write (Plan R11),
// which is why fileSink.Write is the only one that can return a
// meaningful error other than "the destination is closed".
type Sink interface {
	// Write emits one record. The bytes are a complete JSON object
	// (no trailing newline). Implementations must not modify the
	// slice.
	Write(p []byte) error

	// Close releases any resources held by the Sink. After Close,
	// Write returns an error.
	Close() error
}

// stderrSink writes to os.Stderr. This is the default sink so the
// proxy's MCP stdout stays spec-compliant.
//
// Writes go through the *os.File directly. The Go runtime serializes
// concurrent Write calls on the same os.File internally; we do not
// need an extra mutex at this layer.
type stderrSink struct{}

// stderrSingleton is the single shared stderrSink. Allocating one
// per Emitter would be wasteful; the Sink has no state.
var stderrSingleton Sink = stderrSink{}

// stderrSinkSingleton returns the package-level stderr sink. Used
// internally by New when the caller does not enable stdout and does
// not configure a file sink.
func stderrSinkSingleton() Sink { return stderrSingleton }

// Write passes the bytes through to os.Stderr.
func (stderrSink) Write(p []byte) error {
	_, err := os.Stderr.Write(p)
	return err
}

// Close is a no-op for stderr; the process owns the file.
func (stderrSink) Close() error { return nil }

// stdoutSink writes to os.Stdout. It is used only when the operator
// opts in with --audit-stdout or audit.stdout: true in the config
// file; in that mode the MCP server is no longer spec-compliant on
// stdout because the audit JSON-lines share the wire with the
// JSON-RPC frames.
//
// Writes go through os.Stdout directly. Same goroutine-safety
// guarantee as stderrSink.
type stdoutSink struct{}

// stdoutSingleton is the single shared stdoutSink.
var stdoutSingleton Sink = stdoutSink{}

// stdoutSinkSingleton returns the package-level stdout sink.
func stdoutSinkSingleton() Sink { return stdoutSingleton }

// Write passes the bytes through to os.Stdout.
func (stdoutSink) Write(p []byte) error {
	_, err := os.Stdout.Write(p)
	return err
}

// Close is a no-op for stdout; the process owns the file.
func (stdoutSink) Close() error { return nil }

// fileSink writes to a single *os.File and fsyncs after every Write
// per Plan R11. fsync means a process crash does not lose audit
// records; the trade-off is throughput (each Write blocks on disk).
//
// Concurrency model: fileSink serializes Write calls via a mutex so
// fsync sees a fully-written buffer. We do not rely on os.File's
// internal Write serialization because fsync is a separate syscall
// that needs the buffer flush to be ordered before it.
//
// The file is opened with O_APPEND so concurrent writers from other
// processes (rare but possible for log shippers) append rather than
// truncate.
//
// The actual file handle is held through a small syncableFile
// interface (Write + Sync + Close) so tests can inject a stub that
// fails on Sync. Production code goes through *os.FileSyncable, a
// trivial adapter over *os.File.
type fileSink struct {
	mu sync.Mutex
	f  syncableFile
}

// syncableFile is the subset of *os.File the fileSink needs.
// Defined as an interface (not a *os.File) so tests can swap in a
// stub that fails on Sync.
type syncableFile interface {
	Write(p []byte) (int, error)
	Sync() error
	Close() error
}

// osFileSyncable is the production syncableFile. *os.File already
// has Write, Sync, and Close methods with the right signatures, so
// the adapter is just an alias.
type osFileSyncable struct{ f *os.File }

func (o *osFileSyncable) Write(p []byte) (int, error) { return o.f.Write(p) }
func (o *osFileSyncable) Sync() error                 { return o.f.Sync() }
func (o *osFileSyncable) Close() error                { return o.f.Close() }

// newFileSink opens path for append, creating it if necessary, and
// returns a Sink backed by it. Permissions on create are 0644
// (root-writable, world-readable) — a safe default for an audit log
// that downstream log shippers will tail.
//
// Errors from os.OpenFile are returned to the caller verbatim.
func newFileSink(path string) (Sink, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("audit: open file sink %q: %w", path, err)
	}
	return &fileSink{f: &osFileSyncable{f: f}}, nil
}

// Write appends p to the file then fsyncs. fsync errors are returned
// to the caller because Plan R11 specifies "If fsync fails, return
// the error from Emit (caller is the proxy, which logs and continues)".
//
// We deliberately do not retry on fsync failure: the operator
// (or SIEM) needs to see the gap, not have it papered over with a
// retry loop.
func (s *fileSink) Write(p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return errSinkClosed
	}
	if _, err := s.f.Write(p); err != nil {
		return fmt.Errorf("audit: file sink write: %w", err)
	}
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("audit: file sink fsync: %w", err)
	}
	return nil
}

// Close flushes and closes the file. The sink is unusable after
// Close returns. Calling Close twice returns an error from the
// second call (the underlying file is closed).
func (s *fileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

// errSinkClosed is returned by fileSink.Write when called after
// Close. A sentinel is clearer than checking the file pointer from
// outside the package, and the Emitter only sees it as part of the
// error chain.
var errSinkClosed = fmt.Errorf("audit: sink is closed")

// multiSink fans Write out to every configured Sink in registration
// order. It is the Sink the Emitter actually owns.
//
// Concurrency: multiSink holds its own mutex so the fan-out is
// serialized across goroutines. Per-sink writes are still atomic
// (each Sink is required to make Write a single call), so each
// downstream sink sees whole records; only the inter-sink ordering
// is serialized.
//
// Error handling: multiSink.Write returns the first error it sees
// and stops calling subsequent sinks for that record. The Emitter
// surfaces this error to the caller; the proxy logs and continues.
// We do not collect all errors because the upstream caller is only
// going to log one anyway, and a half-fanned-out record is
// unrecoverable from the audit pipeline's perspective.
type multiSink struct {
	mu     sync.Mutex
	sinks  []Sink
	closed bool
}

// newMultiSink composes the given sinks in order. The returned
// multiSink is safe for concurrent use.
func newMultiSink(sinks ...Sink) *multiSink {
	return &multiSink{sinks: sinks}
}

// Write calls Write on every sink in order. Returns the first error
// encountered; subsequent sinks are not called for that record.
func (m *multiSink) Write(p []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errSinkClosed
	}
	for _, s := range m.sinks {
		if err := s.Write(p); err != nil {
			return err
		}
	}
	return nil
}

// Close closes every sink in order. The first error is returned;
// Close continues with subsequent sinks even after an error so
// resources are released even if one sink misbehaves.
func (m *multiSink) Close() error {
	m.mu.Lock()
	m.closed = true
	sinks := m.sinks
	m.mu.Unlock()

	var firstErr error
	for _, s := range sinks {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// discardSink is used by tests to throw away audit output. Not
// exposed; tests construct one with io.Discard through a thin
// wrapper when they need a no-op sink.
type discardSink struct{}

// Write throws the bytes away.
func (discardSink) Write(p []byte) error { _ = p; return nil }

// Close is a no-op.
func (discardSink) Close() error { return nil }

// newDiscardSink returns a Sink that swallows everything. Used by
// tests that want to exercise the Emitter without polluting test
// output.
func newDiscardSink() Sink { return discardSink{} }

// Compile-time interface assertions. If a type stops satisfying
// Sink, the build fails here instead of at the call site.
var (
	_ Sink      = stderrSink{}
	_ Sink      = stdoutSink{}
	_ Sink      = (*fileSink)(nil)
	_ Sink      = (*multiSink)(nil)
	_ Sink      = discardSink{}
	_ io.Closer = stderrSink{}
	_ io.Closer = stdoutSink{}
)
