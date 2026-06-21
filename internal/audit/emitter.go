// Package audit — Emitter layer.
//
// Emitter owns the Sink fan-out and the heartbeat goroutine. It is
// the type the proxy (U4) calls into from the tool-call decision
// path; tests drive it directly to exercise the 6 acceptance
// scenarios from the task brief.
package audit

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"mcp-socd/internal/version"
)

// DefaultHeartbeat is the default heartbeat interval when the
// operator did not configure one. 60s matches Plan §U5: a 60s
// heartbeat so post-hoc analysts can detect a crashed process as a
// gap-in-stream rather than a silent failure.
const DefaultHeartbeat = 60 * time.Second

// Emitter is the OCSF audit emitter. It owns one multiSink (stderr
// by default, plus optional stdout and file) and an optional
// heartbeat goroutine that emits a liveness event every N seconds.
//
// Emitter is safe for concurrent use by many goroutines. The hot
// path (Emit) takes one mutex to serialize JSON marshal + write
// across goroutines so a single record cannot be interleaved with
// another from a different goroutine.
//
// The zero value is NOT ready to use. Construct via New.
type Emitter struct {
	// sink owns the multiSink fan-out. Held under mu.
	sink Sink

	// mu serializes Emit and protects heartbeat fields. The Sink
	// itself is goroutine-safe but we need to coordinate the
	// "emit one whole JSON object" atomicity across goroutines:
	// json.Marshal produces the bytes; we do not want two
	// goroutines' bytes interleaved in the underlying file or
	// pipe.
	mu sync.Mutex

	// heartbeat is the configured heartbeat interval. Zero disables
	// the heartbeat goroutine.
	heartbeat time.Duration

	// stopCh closes to terminate the heartbeat goroutine. nil when
	// heartbeats are disabled.
	stopCh chan struct{}

	// doneCh closes when the heartbeat goroutine has exited. nil
	// when heartbeats are disabled.
	doneCh chan struct{}

	// closed marks the emitter as shut down so Emit returns an
	// error instead of writing through a closed sink.
	closed bool
}

// New constructs an Emitter configured from the audit config block.
// All four cases are handled:
//
//	(stderr only, no heartbeat)   — defaults from R14
//	(stderr + heartbeat)          — production with liveness
//	(stdout + stderr + heartbeat) — --audit-stdout mode
//	(stderr + file + heartbeat)   — production with file audit log
//
// stdout: if true, both stdout AND stderr receive each record so the
// operator can `tee` either stream without losing the other.
//
// heartbeat: <= 0 disables the heartbeat goroutine. > 0 starts a
// ticker that emits class_uid=2004, activity_id=0 events.
//
// file: empty disables the file sink. Non-empty is opened with
// O_APPEND|O_CREATE so existing audit history is preserved across
// restarts. fsync after every write per R11.
//
// Returns an error if the file sink cannot be opened (other sink
// errors are deferred to Emit time).
func New(stdout bool, file string, heartbeat time.Duration) (*Emitter, error) {
	sinks := []Sink{stderrSinkSingleton()}
	if stdout {
		sinks = append(sinks, stdoutSinkSingleton())
	}
	if file != "" {
		fs, err := newFileSink(file)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, fs)
	}

	e := &Emitter{
		sink:      newMultiSink(sinks...),
		heartbeat: heartbeat,
	}

	if heartbeat > 0 {
		e.stopCh = make(chan struct{})
		e.doneCh = make(chan struct{})
		go e.runHeartbeat()
	}

	return e, nil
}

// Emit marshals event to JSON and writes it to every configured sink
// as a single JSON line (record + "\n"). Returns the first error
// from the underlying sinks, or nil on success.
//
// Emit is safe to call concurrently from many goroutines. It does
// NOT overwrite the event's Time, severity, verdict, or any
// per-decision fields — the caller built the event and Emit
// respects it verbatim. The only field Emit mutates is
// metadata.product.version, which is stamped from internal/version
// so the wire format always reflects the build that emitted the
// record.
//
// The event is passed by value so the caller's struct cannot be
// mutated by the (hypothetical) post-conditions of the Sink. Callers
// that want to share an event across goroutines can build once and
// pass copies.
func (e *Emitter) Emit(event Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errSinkClosed
	}

	// Stamp metadata.product.version from the build so the wire
	// format reflects what is running, not what the builder's
	// default was. Done here (not in the builder) so a single
	// Emitter always stamps its own version even if the caller
	// hand-built an Event literal.
	event.Metadata.Product.Version = version.String()

	bytes, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("audit: marshal event: %w", err)
	}
	// Append newline for JSON-lines framing. json.Marshal does
	// not add one because Event is an object, not a list.
	bytes = append(bytes, '\n')

	if err := e.sink.Write(bytes); err != nil {
		return err
	}
	return nil
}

// EmitOCSF is a thin adapter for callers (the proxy in U4) that
// want to pass an opaque value rather than the typed Event. It
// type-asserts event to Event and forwards to Emit. If the
// assertion fails, it returns an error so the caller learns about
// the mismatch immediately rather than silently dropping records.
//
// Kept as a separate method (rather than overloading Emit with an
// any parameter) so the typed path is still available for callers
// that want compile-time guarantees.
func (e *Emitter) EmitOCSF(event any) error {
	ev, ok := event.(Event)
	if !ok {
		return fmt.Errorf("audit: EmitOCSF expects audit.Event, got %T", event)
	}
	return e.Emit(ev)
}

// Heartbeat emits a single class_uid=2004, activity_id=0 liveness
// event. The proxy never calls this directly; the heartbeat
// goroutine does, on its ticker. Tests call it to drive a single
// tick without waiting on the ticker.
//
// The event is stamped with the current time, severity_id=0
// (Unknown — liveness has no severity), verdict label/id=0
// (unset — liveness has no verdict), and a synthetic finding UID
// of "heartbeat-<unix>" so SIEM-side rules can route on it.
func (e *Emitter) Heartbeat() error {
	uid := fmt.Sprintf("heartbeat-%d", time.Now().UTC().Unix())
	return e.Emit(NewBuilder().
		Now().
		WithActivity(ActivityIDOther).
		WithSeverity(Severity0Unknown).
		WithMessage("audit heartbeat").
		WithFindingUID(uid).
		WithFindingTitle("audit heartbeat").
		WithFindingTypes([]string{"audit-heartbeat"}).
		Build())
}

// Close stops the heartbeat goroutine (if any) and closes every
// sink. Returns the first error from sink Close calls; subsequent
// errors are swallowed. After Close, Emit returns errSinkClosed.
//
// Safe to call multiple times; the second call is a no-op.
func (e *Emitter) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	stopCh := e.stopCh
	doneCh := e.doneCh
	e.mu.Unlock()

	if stopCh != nil {
		close(stopCh)
		if doneCh != nil {
			<-doneCh
		}
	}
	return e.sink.Close()
}

// runHeartbeat is the long-running goroutine body. It ticks at the
// configured interval and emits a Heartbeat event each tick. Exits
// when stopCh is closed.
//
// Heartbeat errors are intentionally swallowed: a failed emit
// (typically "file sink fsync failed") is logged by the caller via
// the returned error from Emit, but a heartbeat goroutine cannot
// return errors anywhere. We accept the loss of a single heartbeat
// event over crashing the proxy.
func (e *Emitter) runHeartbeat() {
	defer close(e.doneCh)
	ticker := time.NewTicker(e.heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			_ = e.Heartbeat()
		}
	}
}

// Compile-time guard: Emitter satisfies the shape the proxy (U4)
// will need. Since the proxy package is not yet implemented, we
// assert against a local shim interface so the audit package does
// not import proxy (which would create an import cycle when proxy
// later imports audit — the natural dependency direction is
// proxy -> audit).
//
// When U4 lands, the orchestrator should confirm that proxy.Emitter
// matches this shape:
//
//	type Emitter interface {
//	    EmitOCSF(event any) error
//	}
//
// and call audit.Emitter.EmitOCSF directly. The typed Emit(Event)
// method stays available for in-package and test callers.
type _ProxyEmitterShim interface {
	EmitOCSF(event any) error
}

var _ _ProxyEmitterShim = (*Emitter)(nil)
