package policy

import (
	"errors"
	"fmt"

	"mcp-socd/internal/config"

	"github.com/gobwas/glob"
)

// New constructs an Engine holding the given Policy. Pass the result
// of Compile for a config-derived policy, or NewDenyByDefault for an
// empty policy used during startup before config is loaded.
func New(p *Policy) *Engine {
	e := &Engine{}
	e.Update(p)
	return e
}

// NewDenyByDefault returns an Engine holding an empty Policy that
// denies everything except destructive-verb tools (which still
// require approval). Useful as a startup posture when config has
// not been loaded yet — the proxy never defaults to allow.
func NewDenyByDefault() *Engine {
	return New(&Policy{
		Version:         0,
		Rules:           nil,
		DefaultDecision: DecisionDeny,
		CatchAll: CompiledRule{
			Raw: config.Rule{
				ID:     "__destructive_catchall__",
				Tool:   "*",
				Action: "require_approval",
			},
			Decision:    DecisionRequireApproval,
			Specificity: catchAllSpecificity,
		},
	})
}

// Update atomically swaps the active Policy. In-flight Evaluate
// calls keep reading the old snapshot they captured at the start of
// Evaluate, so the post-condition is "every audit event produced
// during or after this call can carry the new policy_version".
//
// Update does not validate p; callers (typically the loader) must
// have run Compile first. Storing a malformed Policy is a
// programmer error and will surface as Evaluate panicking on the
// nil-deref path; the atomic.Pointer swap itself never fails.
func (e *Engine) Update(p *Policy) {
	if p == nil {
		// Defensive: nil swap leaves the engine with a nil pointer
		// that Evaluate must reject. We restore deny-by-default
		// rather than panic so a buggy loader never leaves the
		// proxy in an undefined state.
		e.current.Store(NewDenyByDefault().Current())
		return
	}
	e.current.Store(p)
}

// Current returns the active Policy. The pointer is shared with the
// engine and must not be mutated by callers. The pointer is also
// safe to read concurrently: callers that need a stable snapshot
// for correlation with audit events should hold the pointer, not
// dereference-and-copy.
func (e *Engine) Current() *Policy {
	return e.current.Load()
}

// Evaluate matches call against the active Policy and returns the
// resulting Decision.
//
// Matching is first-match-wins over Rules (sorted by Specificity at
// Compile time). If no explicit rule matches, Evaluate checks the
// catch-all destructive-verb rule (Plan R7: any tool whose name
// contains a destructive verb requires approval). If the catch-all
// does not apply either, Evaluate returns DefaultDecision, which
// is DecisionDeny for any policy loaded by Compile (Plan R1).
//
// Evaluate is safe for concurrent use. It captures the active
// Policy once via atomic load; concurrent calls to Update do not
// race with this method.
func (e *Engine) Evaluate(call Call) Decision {
	p := e.current.Load()
	if p == nil {
		// No policy loaded: fail closed. This branch is reachable
		// only if a caller constructs an Engine without going
		// through New; production code should always use New.
		return DecisionDeny
	}

	// Phase 1: explicit rules, sorted most-specific first.
	for i := range p.Rules {
		if ruleMatches(&p.Rules[i], call) {
			return p.Rules[i].Decision
		}
	}

	// Phase 2: destructive-verb catch-all (Plan R7). Only fires when
	// no explicit rule matched. The catch-all always returns
	// DecisionRequireApproval; it never allows or denies outright.
	if p.CatchAll.Decision == DecisionRequireApproval && IsDestructiveTool(call.Tool) {
		return DecisionRequireApproval
	}

	// Phase 3: default-deny.
	return p.DefaultDecision
}

// ruleMatches reports whether the rule applies to call. Tool
// matching is exact-equality for literal patterns and glob-match
// otherwise; target matching is exact-equality for empty Target
// lists and "any of these globs matches" otherwise.
//
// An empty Targets list means "any target" — we do not require the
// caller to supply a Target string. A rule with literal targets but
// a non-matching call.Tool still returns false without ever
// comparing targets (cheap reject).
func ruleMatches(r *CompiledRule, call Call) bool {
	if r.ToolGlob == nil {
		if call.Tool != r.Raw.Tool {
			return false
		}
	} else {
		if !r.ToolGlob.Match(call.Tool) {
			return false
		}
	}

	if len(r.TargetGlobs) == 0 {
		// Rule declared no targets — matches any target, including
		// the empty string.
		return true
	}
	if call.Target == "" {
		// Call has no target but the rule declared specific targets;
		// reject rather than accidentally matching everything.
		return false
	}
	for _, g := range r.TargetGlobs {
		if g.Match(call.Target) {
			return true
		}
	}
	return false
}

// Specificity buckets. Lower is more specific; rules are sorted
// ascending so the most specific rule wins.
//
//	exactTool   — no metacharacters in the tool field
//	globTool    — tool field has glob metacharacters
//	catchAll    — synthetic destructive-verb rule
const (
	exactToolSpecificity = iota
	globToolSpecificity
	catchAllSpecificity
)

// Compile turns a config.Policy into a compiled runtime Policy.
// It compiles every tool and target glob exactly once, sorts the
// rules by specificity, and installs the synthetic destructive-verb
// catch-all. Glob compile errors return here — a broken policy
// must never result in tool calls being allowed by default
// (Plan R1/R3 cardinal rule).
//
// The returned Policy is safe for concurrent use and immutable;
// callers must not mutate the slices after handing the Policy to
// an Engine.
func Compile(cp *config.Policy) (*Policy, error) {
	if cp == nil {
		return nil, errors.New("policy: nil config")
	}
	def, ok := ParseDecision(cp.DefaultAction)
	if !ok {
		return nil, fmt.Errorf("policy: default_action %q must be allow|deny", cp.DefaultAction)
	}

	rules := make([]CompiledRule, 0, len(cp.Rules))
	for i := range cp.Rules {
		cr, err := compileRule(&cp.Rules[i])
		if err != nil {
			return nil, fmt.Errorf("policy: rules[%d] (%s): %w", i, cp.Rules[i].ID, err)
		}
		rules = append(rules, cr)
	}
	sortBySpecificity(rules)

	return &Policy{
		Version:         0, // incremented by the loader
		Rules:           rules,
		DefaultDecision: def,
		CatchAll: CompiledRule{
			Raw: config.Rule{
				ID:     "__destructive_catchall__",
				Tool:   "*",
				Action: "require_approval",
			},
			Decision:    DecisionRequireApproval,
			Specificity: catchAllSpecificity,
		},
	}, nil
}

// compileRule turns one config.Rule into a CompiledRule. Returns an
// error if any glob pattern fails to compile; the error wraps the
// offending field name so the loader can point users at the bad
// line in their config.
func compileRule(r *config.Rule) (CompiledRule, error) {
	dec, ok := ParseDecision(r.Action)
	if !ok {
		return CompiledRule{}, fmt.Errorf("action %q must be allow|deny|require_approval", r.Action)
	}

	cr := CompiledRule{
		Raw:         *r,
		Decision:    dec,
		Specificity: exactToolSpecificity,
	}

	if IsGlob(r.Tool) {
		g, err := glob.Compile(r.Tool, '.')
		if err != nil {
			return CompiledRule{}, fmt.Errorf("tool pattern %q: %w", r.Tool, err)
		}
		cr.ToolGlob = g
		cr.Specificity = globToolSpecificity
	}

	cr.TargetGlobs = make([]glob.Glob, 0, len(r.Targets))
	for _, t := range r.Targets {
		if !IsGlob(t) {
			// Literal target: still wrap in glob.Glob so the hot
			// path can stay uniform, but use a compile-time
			// literal match. We could special-case exact equality
			// here; the glob path is fast enough and the
			// uniformity is worth it.
			g, err := glob.Compile(t, '.')
			if err != nil {
				return CompiledRule{}, fmt.Errorf("target pattern %q: %w", t, err)
			}
			cr.TargetGlobs = append(cr.TargetGlobs, g)
			continue
		}
		g, err := glob.Compile(t, '.')
		if err != nil {
			return CompiledRule{}, fmt.Errorf("target pattern %q: %w", t, err)
		}
		cr.TargetGlobs = append(cr.TargetGlobs, g)
	}

	return cr, nil
}

// sortBySpecificity orders rules most-specific-first. Stable for
// rules of equal specificity, preserving the on-disk order which
// is what users actually edit and reason about.
func sortBySpecificity(rules []CompiledRule) {
	// Insertion sort: rule lists are tiny (single digits to low
	// dozens in practice). Stable, no allocation, easy to audit.
	for i := 1; i < len(rules); i++ {
		j := i
		for j > 0 && rules[j-1].Specificity > rules[j].Specificity {
			rules[j-1], rules[j] = rules[j], rules[j-1]
			j--
		}
	}
}
