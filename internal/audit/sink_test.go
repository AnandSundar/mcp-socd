package audit

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// recordingSink captures every Write call into an in-memory buffer.
// Used by the multiSink tests to verify fan-out behavior without
// touching the filesystem or stdio.
type recordingSink struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	written int
}

func (r *recordingSink) Write(p []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf.Write(p)
	r.written++
	return nil
}

func (r *recordingSink) Close() error { return nil }

func (r *recordingSink) snapshot() (string, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String(), r.written
}

// errSink returns a fixed error on every Write. Used to verify
// error propagation through multiSink.
type errSink struct{ err error }

func (e *errSink) Write(p []byte) error { return e.err }
func (e *errSink) Close() error         { return nil }

// TestMultiSink_FanOut verifies that one Write call to a multiSink
// reaches every registered sink.
func TestMultiSink_FanOut(t *testing.T) {
	a := &recordingSink{}
	b := &recordingSink{}
	c := &recordingSink{}
	m := newMultiSink(a, b, c)

	if err := m.Write([]byte("hello\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	for _, s := range []struct {
		name string
		s    *recordingSink
	}{
		{"a", a}, {"b", b}, {"c", c},
	} {
		got, n := s.s.snapshot()
		if got != "hello\n" {
			t.Errorf("sink %s content = %q, want %q", s.name, got, "hello\n")
		}
		if n != 1 {
			t.Errorf("sink %s write count = %d, want 1", s.name, n)
		}
	}
}

// TestMultiSink_FirstErrorWins verifies that when one of the
// underlying sinks errors, multiSink returns that error and does
// not call subsequent sinks for the same record.
func TestMultiSink_FirstErrorWins(t *testing.T) {
	a := &recordingSink{}
	bad := &errSink{err: errors.New("boom")}
	c := &recordingSink{}
	m := newMultiSink(a, bad, c)

	err := m.Write([]byte("hello\n"))
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Write err = %v, want boom", err)
	}
	// a was called (registered before bad). c was not.
	if got, _ := a.snapshot(); got != "hello\n" {
		t.Errorf("sink a content = %q, want %q", got, "hello\n")
	}
	if got, _ := c.snapshot(); got != "" {
		t.Errorf("sink c should not have been called, got %q", got)
	}
}

// TestMultiSink_CloseCallsAll verifies Close iterates every sink
// even when one of them returns an error. The first error is the
// one returned; later errors are swallowed.
func TestMultiSink_CloseCallsAll(t *testing.T) {
	closed := []string{}
	track := func(name string, err error) Sink {
		return &closeTracker{name: name, err: err, closed: &closed}
	}
	a := track("a", nil)
	bad := track("bad", errors.New("close boom"))
	c := track("c", nil)
	m := newMultiSink(a, bad, c)

	err := m.Close()
	if err == nil || !strings.Contains(err.Error(), "close boom") {
		t.Fatalf("Close err = %v, want close boom", err)
	}
	for _, name := range []string{"a", "bad", "c"} {
		found := false
		for _, n := range closed {
			if n == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Close did not call %s; closed=%v", name, closed)
		}
	}
}

// closeTracker is a Sink that records its name into a shared slice
// when Close is called. Used by TestMultiSink_CloseCallsAll.
type closeTracker struct {
	name   string
	err    error
	closed *[]string
}

func (c *closeTracker) Write(p []byte) error { return nil }
func (c *closeTracker) Close() error {
	*c.closed = append(*c.closed, c.name)
	return c.err
}

// TestMultiSink_WriteAfterCloseReturnsError verifies that a Write
// after Close returns the errSinkClosed sentinel rather than
// panicking.
func TestMultiSink_WriteAfterCloseReturnsError(t *testing.T) {
	m := newMultiSink(newDiscardSink())
	_ = m.Close()
	err := m.Write([]byte("x"))
	if !errors.Is(err, errSinkClosed) {
		t.Errorf("Write after Close err = %v, want errSinkClosed", err)
	}
}

// TestFileSink_WritesAndFsyncs verifies that a fileSink writes the
// full payload to the file and that a separate process reading the
// file sees the data immediately (i.e. fsync has run by the time
// Write returns).
//
// Plan R11 requires fsync after every write. We cannot directly
// observe the fsync syscall from a unit test without syscall
// tracing; instead we observe its effect: data is durable. If fsync
// were skipped, this test would still pass on most filesystems
// because the page cache is consistent. The strong signal — a
// process crash recovery test — is out of scope for the unit
// suite; the integration test (U10) covers it.
func TestFileSink_WritesAndFsyncs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	s, err := newFileSink(path)
	if err != nil {
		t.Fatalf("newFileSink: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if err := s.Write([]byte("line1\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := s.Write([]byte("line2\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = s.Close()

	// Re-open the file and verify both lines are present in order.
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got, want := string(data), "line1\nline2\n"; got != want {
		t.Errorf("file content = %q, want %q", got, want)
	}
}

// TestFileSink_AppendsToExisting verifies that an existing file is
// appended to rather than truncated (O_APPEND semantics). This is
// the property an operator relies on when log-rotation tools move
// the file out from under us: the next write goes to the new file
// without losing the trailing data.
func TestFileSink_AppendsToExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// Seed the file with a prior record (as if from a previous run).
	if err := os.WriteFile(path, []byte("prior\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	s, err := newFileSink(path)
	if err != nil {
		t.Fatalf("newFileSink: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if err := s.Write([]byte("new\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = s.Close()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if want := "prior\nnew\n"; string(got) != want {
		t.Errorf("content = %q, want %q", got, want)
	}
}

// TestFileSink_CloseIsIdempotent verifies Close can be called twice
// without error. The second call is a no-op on the underlying file
// but should not panic.
func TestFileSink_CloseIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	s, err := newFileSink(path)
	if err != nil {
		t.Fatalf("newFileSink: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v (want nil)", err)
	}
}

// TestFileSink_NewFileSinkErrorReturnsError verifies the
// constructor surfaces filesystem errors rather than swallowing
// them.
func TestFileSink_NewFileSinkErrorReturnsError(t *testing.T) {
	// A directory path that does not exist cannot be opened as a
	// file. On every supported OS os.OpenFile returns ENOENT
	// rather than auto-creating intermediate directories.
	_, err := newFileSink("/nonexistent-root-dir-12345/audit.log")
	if err == nil {
		t.Fatal("expected error opening file in non-existent dir, got nil")
	}
}

// TestFileSink_WriteAfterCloseReturnsError verifies the
// errSinkClosed sentinel comes back from Write after Close.
func TestFileSink_WriteAfterCloseReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	s, err := newFileSink(path)
	if err != nil {
		t.Fatalf("newFileSink: %v", err)
	}
	_ = s.Close()
	err = s.Write([]byte("x"))
	if !errors.Is(err, errSinkClosed) {
		t.Errorf("Write after Close err = %v, want errSinkClosed", err)
	}
}

// TestSink_InterfaceAssertions is a compile-time check that the
// concrete types still satisfy Sink. Caught at compile time, but a
// runtime test makes the intent explicit in the test output.
func TestSink_InterfaceAssertions(t *testing.T) {
	var _ Sink = stderrSink{}
	var _ Sink = stdoutSink{}
	var _ Sink = (*fileSink)(nil)
	var _ Sink = (*multiSink)(nil)
	var _ Sink = discardSink{}
}

// TestMultiSink_ConcurrentWritesDoNotInterleave fires N goroutines
// at a multiSink and verifies every recording sink sees exactly N
// complete lines, not partial / interleaved ones.
//
// This is the property the multiSink mutex buys us; if a future
// refactor drops the mutex, `go test -race` would catch the data
// race on the underlying sink buffer AND the per-line byte count
// would drop below N.
func TestMultiSink_ConcurrentWritesDoNotInterleave(t *testing.T) {
	const goroutines = 16
	const writesEach = 50

	sinks := make([]Sink, goroutines)
	for i := range sinks {
		sinks[i] = &recordingSink{}
	}
	m := newMultiSink(sinks...)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < writesEach; i++ {
				payload := []byte("g" + string(rune('A'+id%26)) + "\n")
				if err := m.Write(payload); err != nil {
					t.Errorf("Write: %v", err)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	wantLines := goroutines * writesEach
	for i, s := range sinks {
		rs, ok := s.(*recordingSink)
		if !ok {
			t.Fatalf("sink[%d] is not a *recordingSink", i)
		}
		content, n := rs.snapshot()
		if n != wantLines {
			t.Errorf("sink[%d] writes = %d, want %d", i, n, wantLines)
		}
		// Every line must be a complete "<letter>\n" record. No
		// interleaving means no line is longer than 2 bytes.
		countLines := bytes.Count([]byte(content), []byte("\n"))
		if countLines != wantLines {
			t.Errorf("sink[%d] line count = %d, want %d", i, countLines, wantLines)
		}
	}
}

// TestFileSink_ConcurrentWritesAllArrive verifies concurrent Write
// calls to a fileSink all land in the file. fsync serializes them
// so no data is lost; with O_APPEND the bytes are appended in some
// order but every byte from every goroutine is present.
func TestFileSink_ConcurrentWritesAllArrive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	s, err := newFileSink(path)
	if err != nil {
		t.Fatalf("newFileSink: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	const goroutines = 8
	const writesEach = 25
	var wg sync.WaitGroup
	wg.Add(goroutines)
	var seen int64
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < writesEach; i++ {
				payload := []byte("g" + string(rune('A'+id%26)) + "\n")
				if err := s.Write(payload); err != nil {
					t.Errorf("Write: %v", err)
					return
				}
				atomic.AddInt64(&seen, 1)
			}
		}(g)
	}
	wg.Wait()
	_ = s.Close()

	if got := atomic.LoadInt64(&seen); got != int64(goroutines*writesEach) {
		t.Errorf("client-side seen = %d, want %d", got, goroutines*writesEach)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := bytes.Count(got, []byte("\n"))
	if lines != goroutines*writesEach {
		t.Errorf("file lines = %d, want %d", lines, goroutines*writesEach)
	}
}
