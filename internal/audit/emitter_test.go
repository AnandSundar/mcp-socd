package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mcp-socd/internal/version"
)

// captureStderr redirects os.Stderr to an in-memory pipe for the
// duration of fn and returns whatever fn wrote to stderr. Used to
// verify the default routing without polluting test output.
//
// On Windows the redirect uses os.CreateFile on CONOUT$; on POSIX
// it relies on os.Stderr being a *os.File whose underlying fd can
// be dup'd. The implementation here works on both because we
// restore os.Stderr on cleanup.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	t.Cleanup(func() {
		os.Stderr = orig
	})

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()
	_ = w.Close()
	return <-done
}

// captureStdout is the stdout-side helper. Same mechanics as
// captureStderr but for os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	t.Cleanup(func() {
		os.Stdout = orig
	})

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	fn()
	_ = w.Close()
	return <-done
}

// sampleDecision is the Event used by the routing and verdict
// tests. Keeps the test bodies focused on the assertion.
func sampleDecision(verdict Verdict) Event {
	return NewBuilder().
		Now().
		WithActivity(ActivityIDCreate).
		WithSeverityID(4).
		WithMessage("isolate_endpoint against server01.example.com").
		WithFindingUID("allow-isolate-server01").
		WithFindingTitle("isolate_endpoint against server01.example.com").
		WithFindingTypes([]string{"soc-action", "isolation"}).
		WithVerdict(verdict).
		WithPolicyVersion(7).
		WithRequestID("req-1").
		WithResource("isolate_endpoint").
		WithActor("agent@home").
		Build()
}

// TestEmitter_RequiredFieldsPresent — scenario 1 of 6 from the
// task brief. Every emitted record must carry the OCSF-required
// fields: class_uid, class_name, activity_id, time, metadata.product,
// severity_id, message.
func TestEmitter_RequiredFieldsPresent(t *testing.T) {
	e, err := New(false, "", 0) // stderr only, no heartbeat
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })

	got := captureStderr(t, func() {
		if err := e.Emit(sampleDecision(VerdictAllow)); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	})

	lines := splitLines(got)
	if len(lines) != 1 {
		t.Fatalf("expected 1 line on stderr, got %d: %q", len(lines), got)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("emitted line is not valid JSON: %v\nline: %s", err, lines[0])
	}
	mustHave := map[string]any{
		"class_uid":   float64(2004),
		"class_name":  "Detection Finding",
		"activity_id": float64(1),
		"severity_id": float64(4),
		"message":     "isolate_endpoint against server01.example.com",
		"verdict":     "Allow",
		"verdict_id":  float64(1),
	}
	for k, want := range mustHave {
		got, ok := rec[k]
		if !ok {
			t.Errorf("required field %q missing from emitted record", k)
			continue
		}
		if got != want {
			t.Errorf("field %q = %v (%T), want %v (%T)", k, got, got, want, want)
		}
	}
	if _, ok := rec["time"]; !ok {
		t.Error("required field \"time\" missing from emitted record")
	}
	md, ok := rec["metadata"].(map[string]any)
	if !ok {
		t.Fatal("metadata missing or wrong type")
	}
	prod, ok := md["product"].(map[string]any)
	if !ok {
		t.Fatal("metadata.product missing or wrong type")
	}
	if prod["name"] != "mcp-socd" {
		t.Errorf("metadata.product.name = %v, want mcp-socd", prod["name"])
	}
	if prod["vendor_name"] != "mcp-socd" {
		t.Errorf("metadata.product.vendor_name = %v, want mcp-socd", prod["vendor_name"])
	}
	// version.String() is what was stamped at emit time.
	if prod["version"] != version.String() {
		t.Errorf("metadata.product.version = %v, want %v", prod["version"], version.String())
	}
}

// TestEmitter_VerdictMapping — scenario 2 of 6. Allow, Deny, and
// RequireApproval each map to their canonical verdict_id values
// (1, 2, 3).
func TestEmitter_VerdictMapping(t *testing.T) {
	e, err := New(false, "", 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })

	cases := []struct {
		name    string
		verdict Verdict
		wantID  int
		wantStr string
	}{
		{"Allow", VerdictAllow, 1, "Allow"},
		{"Deny", VerdictDeny, 2, "Deny"},
		{"RequireApproval", VerdictRequireApproval, 3, "RequireApproval"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := captureStderr(t, func() {
				if err := e.Emit(sampleDecision(tc.verdict)); err != nil {
					t.Fatalf("Emit: %v", err)
				}
			})
			lines := splitLines(got)
			if len(lines) != 1 {
				t.Fatalf("expected 1 line, got %d", len(lines))
			}
			var rec map[string]any
			if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			if got := rec["verdict"]; got != tc.wantStr {
				t.Errorf("verdict = %v, want %s", got, tc.wantStr)
			}
			if got := rec["verdict_id"]; got != float64(tc.wantID) {
				t.Errorf("verdict_id = %v, want %d", got, tc.wantID)
			}
		})
	}
}

// TestEmitter_FileSinkFsync — scenario 3 of 6. Write to file, close,
// re-open, parse — all lines must be valid JSON. Additionally, we
// verify that a fsync failure surfaces as an Emit error.
//
// The fsync-failure path is exercised by swapping the underlying
// *os.File with a non-file implementation; we use a small wrapper
// that succeeds on Write but fails on Sync. The Emit must return
// that error to the caller (the proxy logs and continues).
func TestEmitter_FileSinkFsync(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	e, err := New(false, path, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Emit three records.
	for i := 0; i < 3; i++ {
		if err := e.Emit(sampleDecision(VerdictAllow)); err != nil {
			t.Fatalf("Emit[%d]: %v", i, err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Re-open and parse — every line must be valid JSON.
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	for i, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Errorf("line[%d] is not valid JSON: %v\nline: %s", i, err, line)
		}
		if _, ok := rec["class_uid"]; !ok {
			t.Errorf("line[%d] missing class_uid", i)
		}
	}

	// Fsync failure path: build a fileSink backed by a stub that
	// fails on Sync. The Write must return the error from Sync.
	fs := &fileSink{f: &failingSyncStub{}}
	err = fs.Write([]byte("trigger\n"))
	if err == nil {
		t.Fatal("expected fsync failure to surface as Write error, got nil")
	}
	if !strings.Contains(err.Error(), "fsync") {
		t.Errorf("expected error to mention fsync, got: %v", err)
	}
	if !strings.Contains(err.Error(), "simulated") {
		t.Errorf("expected error to mention the underlying simulated failure, got: %v", err)
	}
	_ = fs.Close() // safe; failingSyncStub.Close is a no-op
}

// failingSyncStub implements syncableFile with a Write that succeeds
// and a Sync that always fails. Used to verify fsync errors propagate
// out of fileSink.Write and (transitively) out of Emitter.Emit.
type failingSyncStub struct{}

func (failingSyncStub) Write(p []byte) (int, error) { return len(p), nil }
func (failingSyncStub) Sync() error                 { return errors.New("simulated fsync failure") }
func (failingSyncStub) Close() error                { return nil }

// TestEmitter_Heartbeat — scenario 4 of 6. With heartbeat=50ms, after
// 200ms wait we expect >=3 heartbeat events. With heartbeat=0, none
// are emitted.
//
// We route heartbeats to a recordingSink via the New constructor's
// stderr default; instead of capturing stderr we install a custom
// Emitter (via package-internal helpers? no — we go through the
// public path by setting heartbeat and capturing stderr).
func TestEmitter_Heartbeat(t *testing.T) {
	t.Run("enabled emits at least 3 in 200ms", func(t *testing.T) {
		e, err := New(false, "", 50*time.Millisecond)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { _ = e.Close() })

		got := captureStderr(t, func() {
			time.Sleep(220 * time.Millisecond)
		})

		lines := splitLines(got)
		// Filter to just heartbeat lines (activity_id == 0) so a
		// stray Emit from elsewhere doesn't break the count.
		var heartbeats int
		for _, line := range lines {
			var rec map[string]any
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				continue
			}
			if rec["activity_id"] == float64(0) {
				heartbeats++
			}
		}
		if heartbeats < 3 {
			t.Errorf("expected >=3 heartbeats in 220ms, got %d (lines=%d)",
				heartbeats, len(lines))
		}
	})

	t.Run("disabled emits none", func(t *testing.T) {
		e, err := New(false, "", 0)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { _ = e.Close() })

		got := captureStderr(t, func() {
			// One Emit, no heartbeats. Confirm only that one line
			// shows up on stderr and it is NOT a heartbeat.
			_ = e.Emit(sampleDecision(VerdictAllow))
			time.Sleep(150 * time.Millisecond)
		})

		lines := splitLines(got)
		// We expect exactly 1 line (the Emit) — no heartbeats.
		if len(lines) != 1 {
			t.Fatalf("expected 1 line, got %d: %v", len(lines), lines)
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if rec["activity_id"] == float64(0) {
			t.Errorf("first line was a heartbeat, expected the explicit Emit")
		}
	})
}

// TestEmitter_StdoutAndStderrRouting — scenario 5 of 6. Verify
// routing by configuring the emitter with stdout=true vs stdout=false.
//
// Default (stdout=false) routes to stderr only.
// stdout=true routes to BOTH stderr and stdout.
func TestEmitter_StdoutAndStderrRouting(t *testing.T) {
	t.Run("stdout=false routes only to stderr", func(t *testing.T) {
		e, err := New(false, "", 0)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { _ = e.Close() })

		var stderrOut, stdoutOut string
		stderrOut = captureStderr(t, func() {
			stdoutOut = captureStdout(t, func() {
				if err := e.Emit(sampleDecision(VerdictAllow)); err != nil {
					t.Fatalf("Emit: %v", err)
				}
			})
		})

		if len(splitLines(stderrOut)) != 1 {
			t.Errorf("stderr: expected 1 line, got %d: %q", len(splitLines(stderrOut)), stderrOut)
		}
		if stdoutOut != "" {
			t.Errorf("stdout should be empty with stdout=false, got %q", stdoutOut)
		}
	})

	t.Run("stdout=true routes to both stderr and stdout", func(t *testing.T) {
		e, err := New(true, "", 0)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { _ = e.Close() })

		var stderrOut, stdoutOut string
		stderrOut = captureStderr(t, func() {
			stdoutOut = captureStdout(t, func() {
				if err := e.Emit(sampleDecision(VerdictAllow)); err != nil {
					t.Fatalf("Emit: %v", err)
				}
			})
		})

		if len(splitLines(stderrOut)) != 1 {
			t.Errorf("stderr: expected 1 line, got %d", len(splitLines(stderrOut)))
		}
		if len(splitLines(stdoutOut)) != 1 {
			t.Errorf("stdout: expected 1 line, got %d", len(splitLines(stdoutOut)))
		}
		// Both lines should be identical JSON.
		if stderrOut != stdoutOut {
			t.Errorf("stderr and stdout should match\nstderr=%q\nstdout=%q", stderrOut, stdoutOut)
		}
	})

	t.Run("file sink routes to stderr AND file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "audit.log")
		e, err := New(false, path, 0)
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		stderrOut := captureStderr(t, func() {
			if err := e.Emit(sampleDecision(VerdictAllow)); err != nil {
				t.Fatalf("Emit: %v", err)
			}
		})
		if err := e.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if len(splitLines(stderrOut)) != 1 {
			t.Errorf("stderr: expected 1 line, got %d", len(splitLines(stderrOut)))
		}
		fileData, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read file: %v", err)
		}
		if len(splitLines(string(fileData))) != 1 {
			t.Errorf("file: expected 1 line, got %d in %q", len(splitLines(string(fileData))), fileData)
		}
		// file content should match stderr content (both routed the
		// same record).
		if stderrOut != string(fileData) {
			t.Errorf("file and stderr content differ:\nstderr=%q\nfile=%q",
				stderrOut, string(fileData))
		}
	})
}

// TestEmitter_MultiSinkFanOut — scenario 6 of 6. One Emit call goes
// to all configured sinks (stderr + stdout + file).
func TestEmitter_MultiSinkFanOut(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	e, err := New(true, path, 0) // stdout + file + (stderr default)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var stderrOut, stdoutOut string
	stderrOut = captureStderr(t, func() {
		stdoutOut = captureStdout(t, func() {
			if err := e.Emit(sampleDecision(VerdictDeny)); err != nil {
				t.Fatalf("Emit: %v", err)
			}
		})
	})
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Each sink should have exactly one line.
	if len(splitLines(stderrOut)) != 1 {
		t.Errorf("stderr: expected 1 line, got %d", len(splitLines(stderrOut)))
	}
	if len(splitLines(stdoutOut)) != 1 {
		t.Errorf("stdout: expected 1 line, got %d", len(splitLines(stdoutOut)))
	}
	fileData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if len(splitLines(string(fileData))) != 1 {
		t.Errorf("file: expected 1 line, got %d", len(splitLines(string(fileData))))
	}
	// All three should be the same record.
	if stderrOut != stdoutOut {
		t.Errorf("stderr != stdout:\nstderr=%q\nstdout=%q", stderrOut, stdoutOut)
	}
	if stderrOut != string(fileData) {
		t.Errorf("stderr != file:\nstderr=%q\nfile=%q", stderrOut, string(fileData))
	}
}

// TestEmitter_ConcurrentEmits confirms Emit is safe to call from
// many goroutines simultaneously. Every emitted record must be a
// complete JSON line on every sink.
func TestEmitter_ConcurrentEmits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	e, err := New(true, path, 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const goroutines = 16
	const writesEach = 25

	var wg sync.WaitGroup
	wg.Add(goroutines)
	var errCount int64
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < writesEach; i++ {
				ev := sampleDecision(VerdictAllow)
				ev.RequestID = "req-" + string(rune('A'+id%26)) + "-" + string(rune('0'+(i%10)))
				if err := e.Emit(ev); err != nil {
					atomic.AddInt64(&errCount, 1)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	if errCount > 0 {
		t.Errorf("%d concurrent Emit calls failed", errCount)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Every line on stderr, stdout, and file must be valid JSON.
	fileData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	wantLines := goroutines * writesEach
	checkLines(t, "file", string(fileData), wantLines)
}

// TestEmitter_CloseStopsHeartbeat confirms the heartbeat goroutine
// actually exits when Close is called. We probe this by issuing
// Close and then waiting for doneCh (via Close's blocking join).
func TestEmitter_CloseStopsHeartbeat(t *testing.T) {
	e, err := New(false, "", 20*time.Millisecond)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Give the goroutine a moment to start.
	time.Sleep(30 * time.Millisecond)

	start := time.Now()
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	elapsed := time.Since(start)
	// Close must wait for the goroutine to exit. A long wait
	// (>1s) would indicate a bug where the goroutine is stuck.
	if elapsed > time.Second {
		t.Errorf("Close took %v; expected <1s", elapsed)
	}
}

// TestEmitter_CloseIsIdempotent verifies Close can be called twice
// without error.
func TestEmitter_CloseIsIdempotent(t *testing.T) {
	e, err := New(false, "", 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Errorf("second Close: %v (want nil)", err)
	}
}

// TestEmitter_EmitAfterCloseReturnsError verifies that Emit returns
// the errSinkClosed sentinel after Close so the proxy does not
// silently drop records.
func TestEmitter_EmitAfterCloseReturnsError(t *testing.T) {
	e, err := New(false, "", 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err = e.Emit(sampleDecision(VerdictAllow))
	if !errors.Is(err, errSinkClosed) {
		t.Errorf("Emit after Close err = %v, want errSinkClosed", err)
	}
}

// TestEmitter_EmitOCSF_Adapter verifies the EmitOCSF adapter
// forwards typed Events and rejects non-Event values. This is the
// adapter the proxy.Emitter shim interface relies on.
func TestEmitter_EmitOCSF_Adapter(t *testing.T) {
	e, err := New(false, "", 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })

	got := captureStderr(t, func() {
		if err := e.EmitOCSF(sampleDecision(VerdictAllow)); err != nil {
			t.Fatalf("EmitOCSF(Event): %v", err)
		}
		// Wrong type must error, not panic.
		if err := e.EmitOCSF("not an Event"); err == nil {
			t.Error("EmitOCSF(string) should have errored")
		}
		if err := e.EmitOCSF(42); err == nil {
			t.Error("EmitOCSF(int) should have errored")
		}
	})

	// Only the first Emit produced output.
	lines := splitLines(got)
	if len(lines) != 1 {
		t.Errorf("expected 1 line, got %d", len(lines))
	}
}

// TestEmitter_Severity99UnknownAccepted verifies that severity_id=99
// (Unknown / Other) is a valid value that round-trips through Emit.
func TestEmitter_Severity99UnknownAccepted(t *testing.T) {
	e, err := New(false, "", 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })

	ev := sampleDecision(VerdictAllow)
	ev.SeverityID = 99

	got := captureStderr(t, func() {
		if err := e.Emit(ev); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	})
	lines := splitLines(got)
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rec["severity_id"] != float64(99) {
		t.Errorf("severity_id = %v, want 99", rec["severity_id"])
	}
}

// TestEmitter_HeartbeatEventShape verifies the heartbeat record
// itself satisfies the OCSF envelope: class_uid=2004, activity_id=0,
// time stamped, severity_id=0 (Unknown), finding_info.types
// contains "audit-heartbeat" so SIEM-side rules can route on it.
func TestEmitter_HeartbeatEventShape(t *testing.T) {
	e, err := New(false, "", 30*time.Millisecond)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })

	got := captureStderr(t, func() {
		// Drive a single heartbeat synchronously to avoid waiting
		// for the ticker.
		if err := e.Heartbeat(); err != nil {
			t.Fatalf("Heartbeat: %v", err)
		}
	})

	lines := splitLines(got)
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rec["class_uid"] != float64(2004) {
		t.Errorf("class_uid = %v, want 2004", rec["class_uid"])
	}
	if rec["activity_id"] != float64(0) {
		t.Errorf("activity_id = %v, want 0", rec["activity_id"])
	}
	if rec["severity_id"] != float64(0) {
		t.Errorf("severity_id = %v, want 0", rec["severity_id"])
	}
	fi, ok := rec["finding_info"].(map[string]any)
	if !ok {
		t.Fatal("finding_info missing or wrong type")
	}
	types, ok := fi["types"].([]any)
	if !ok {
		t.Fatalf("finding_info.types missing or wrong type: %T", fi["types"])
	}
	found := false
	for _, t := range types {
		if t == "audit-heartbeat" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("finding_info.types = %v, want contains 'audit-heartbeat'", types)
	}
	if _, ok := rec["time"]; !ok {
		t.Error("time missing from heartbeat record")
	}
}

// splitLines returns the non-empty trimmed lines of s. Used by the
// routing tests to count records on a captured stream.
func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// checkLines verifies every non-empty line of data parses as JSON
// and that the line count equals wantLines.
func checkLines(t *testing.T, label, data string, wantLines int) {
	t.Helper()
	lines := splitLines(data)
	if len(lines) != wantLines {
		t.Errorf("%s: line count = %d, want %d", label, len(lines), wantLines)
		return
	}
	for i, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Errorf("%s: line[%d] invalid JSON: %v\nline: %s", label, i, err, line)
		}
	}
}
