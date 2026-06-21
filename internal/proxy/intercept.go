package proxy

import (
	"encoding/json"
	"fmt"

	"mcp-socd/internal/catalog"
	"mcp-socd/internal/policy"
)

// Emitter is the audit hook the intercept path calls for every
// decision (allow, deny, require_approval, schema reject, etc.).
// U4 ships a NoopEmitter default; U5 will plug in an OCSF Detection
// Finding emitter that satisfies this interface without U4 having to
// import internal/audit.
//
// The contract is intentionally narrow: the intercept path passes a
// fully-formed map of decision metadata. The emitter owns the
// serialization (to stderr/stdout/file per Plan §KTD5) and the
// buffering/flush semantics. Returning an error from Emit is treated
// as advisory: the proxy logs it via fmt.Fprintf(os.Stderr, ...) but
// does not block the tool call. Audit failures must never be the
// reason an action is denied (Plan R14: emit-or-leak, but never
// fail-closed on audit).
type Emitter interface {
	// Emit writes one audit event. event is a map of decision
	// metadata keyed by string. Implementations may serialize to
	// JSON-lines, OCSF Detection Finding, or any other shape; the
	// proxy does not impose structure beyond the keys it sets.
	Emit(event map[string]any)
}

// NoopEmitter is the default Emitter used when the caller does not
// supply one. It satisfies Emitter by doing nothing; tests use it
// directly and production code will replace it with the U5
// implementation.
type NoopEmitter struct{}

// Emit implements Emitter.
func (NoopEmitter) Emit(map[string]any) {}

// StderrEmitter is a debug-only Emitter that writes each event as a
// single JSON line to the supplied writer. It exists so U4 tests can
// verify the intercept path produces the expected decision metadata
// without pulling in the full U5 audit stack. U5 will supersede this
// with the production OCSF emitter.
type StderrEmitter struct {
	// Sink receives one JSON-line per Emit call. Tests pass an
	// in-memory buffer; production callers can pass os.Stderr to
	// observe the audit stream during integration runs.
	Sink interface {
		Write(p []byte) (int, error)
	}
}

// Emit implements Emitter by encoding event as a single JSON object
// terminated by a newline.
func (s StderrEmitter) Emit(event map[string]any) {
	if s.Sink == nil {
		return
	}
	b, err := json.Marshal(event)
	if err != nil {
		// Fall back to fmt.Sprintf so a non-serializable event still
		// surfaces in the audit sink rather than vanishing silently.
		b = []byte(fmt.Sprintf("%+v", event))
	}
	b = append(b, '\n')
	_, _ = s.Sink.Write(b)
}

// ToolsCallParams is the JSON-RPC params shape for a tools/call
// request. MCP defines method + arguments; we decode just enough to
// route the call (tool name + argument map) and forward the rest of
// the params verbatim to the upstream server.
//
// Both fields use permissive types: Name is a string (the spec
// requires it), Arguments is a map (the spec requires an object;
// agents may also send null, in which case we treat it as an empty
// map).
type ToolsCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// InterceptResult is the outcome of evaluating a tools/call request.
// It carries either a synthetic response to relay back to the agent
// (Forward == false) or a flag indicating the caller should forward
// the original request to the upstream server (Forward == true).
//
// The synthetic response is fully formed JSON-RPC; callers write it
// straight to the agent without further transformation.
type InterceptResult struct {
	// Forward indicates the caller should relay the original
	// request to the upstream server untouched.
	Forward bool

	// Synthetic is the JSON-RPC response bytes to send to the agent
	// when Forward is false. Ignored when Forward is true.
	Synthetic []byte
}

// interceptCall evaluates a tools/call request against the catalog
// and policy engine, then decides whether to forward it to the
// upstream server or return a synthetic response.
//
// Decision pipeline (Plan §"Tool-call flow"):
//
//  1. decode params; if malformed return a synthetic JSON-RPC error
//     with code CodeInvalidParams.
//  2. validate arguments against the action's JSON-Schema; on
//     violation return CodeInvalidParams with the schema error.
//  3. extract the call's target (the first non-empty scalar argument
//     in canonical order: host_id, user_id, key_id, indicator,
//     otherwise empty).
//  4. evaluate the policy.Engine with (tool, target, arguments).
//  5. emit an audit event keyed by the decision (allow/deny/
//     require_approval). Audit emission is best-effort: the
//     emitter's errors are not surfaced to the agent.
//  6. build the InterceptResult:
//     - DecisionAllow       -> Forward == true
//     - DecisionDeny        -> Synthetic JSON-RPC error with
//     CodePolicyDenied and a structured
//     data payload (reason, rule_id).
//     - DecisionRequireApproval -> Synthetic JSON-RPC error with
//     CodePolicyDenied and reason
//     "approval_pending" so the agent
//     pauses; U6 will replace this with
//     the real approval-workflow bridge.
func interceptCall(
	req *Request,
	engine *policy.Engine,
	cat *catalog.Catalog,
	emitter Emitter,
) InterceptResult {
	params, perr := decodeToolsCallParams(req.Params)
	if perr != nil {
		emitter.Emit(map[string]any{
			"decision": "error",
			"reason":   "params_decode_failed",
			"error":    perr.Error(),
			"method":   req.Method,
		})
		body, _ := EncodeErrorResponse(req, CodeInvalidParams,
			"tools/call: invalid params: "+perr.Error(), nil)
		return InterceptResult{Synthetic: body}
	}

	if verr := cat.Validate(params.Name, params.Arguments); verr != nil {
		emitter.Emit(map[string]any{
			"decision": "error",
			"reason":   "schema_violation",
			"tool":     params.Name,
			"error":    verr.Error(),
		})
		body, _ := EncodeErrorResponse(req, CodeInvalidParams,
			"tools/call: "+verr.Error(), nil)
		return InterceptResult{Synthetic: body}
	}

	target := extractTarget(params.Name, params.Arguments)
	decision := engine.Evaluate(policy.Call{
		Tool:      params.Name,
		Target:    target,
		Arguments: params.Arguments,
	})

	emitter.Emit(map[string]any{
		"decision": decision.String(),
		"tool":     params.Name,
		"target":   target,
	})

	switch decision {
	case policy.DecisionAllow:
		return InterceptResult{Forward: true}

	case policy.DecisionDeny:
		body, _ := EncodeErrorResponse(req, CodePolicyDenied,
			"tool call denied by policy",
			map[string]any{
				"reason":  "policy_deny",
				"tool":    params.Name,
				"target":  target,
				"version": engine.Current().Version,
			})
		return InterceptResult{Synthetic: body}

	case policy.DecisionRequireApproval:
		// U6 will replace this with the real approval-workflow bridge
		// that blocks until the human responds. For U4 we synthesize a
		// JSON-RPC error so the agent can distinguish "needs approval"
		// from outright denial; U6 swaps the error code and message
		// without changing the InterceptResult shape.
		body, _ := EncodeErrorResponse(req, CodePolicyDenied,
			"awaiting out-of-band approval (U6 not yet wired)",
			map[string]any{
				"reason":  "approval_pending",
				"tool":    params.Name,
				"target":  target,
				"version": engine.Current().Version,
			})
		return InterceptResult{Synthetic: body}

	default:
		// DecisionUnset or any future value: fail closed.
		body, _ := EncodeErrorResponse(req, CodePolicyDenied,
			"tool call denied: policy returned no decision",
			map[string]any{
				"reason":  "policy_unset",
				"tool":    params.Name,
				"target":  target,
				"version": engine.Current().Version,
			})
		return InterceptResult{Synthetic: body}
	}
}

// decodeToolsCallParams unmarshals req.Params into a ToolsCallParams.
// Returns a non-nil error when params is not a JSON object, when the
// name field is missing or non-string, or when the JSON itself is
// invalid.
func decodeToolsCallParams(raw json.RawMessage) (ToolsCallParams, error) {
	if len(raw) == 0 {
		return ToolsCallParams{}, fmt.Errorf("params is empty")
	}
	var p ToolsCallParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return ToolsCallParams{}, fmt.Errorf("params not a JSON object: %w", err)
	}
	if p.Name == "" {
		return ToolsCallParams{}, fmt.Errorf("params.name is required")
	}
	return p, nil
}

// targetArgNames is the canonical order in which the proxy looks for
// a "primary" argument to feed the policy engine's Target field. The
// order reflects the starter catalog's per-action argument conventions;
// unknown tools fall through to "" (empty target), which the policy
// engine treats as "any target" for rules that allow it.
var targetArgNames = []string{"host_id", "user_id", "key_id", "indicator", "query"}

// extractTarget picks the first non-empty scalar argument from args,
// consulting targetArgNames in order. Returns "" when no candidate is
// present or when the value is not a string.
//
// The starter catalog encodes the primary target as a named string
// argument (host_id for isolate_endpoint, user_id for
// block_user_account, etc.). Custom actions that follow the same
// convention will be matched automatically; non-conforming actions
// fall through with Target == "", which is a valid policy input (rules
// with no targets declared match anything).
func extractTarget(tool string, args map[string]any) string {
	for _, k := range targetArgNames {
		if v, ok := args[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}
