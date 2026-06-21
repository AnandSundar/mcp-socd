package policy

import (
	"sync"
	"testing"

	"mcp-socd/internal/config"
)

// mustCompile wraps Compile and fails the test on error. Used to
// keep the body of each test focused on the scenario, not on
// boilerplate.
func mustCompile(t *testing.T, cp *config.Policy) *Policy {
	t.Helper()
	p, err := Compile(cp)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return p
}

// TestEngine_AllowOnMatch — exact target match yields Allow (Plan U3).
func TestEngine_AllowOnMatch(t *testing.T) {
	p := mustCompile(t, &config.Policy{
		DefaultAction: "deny",
		Rules: []config.Rule{
			{
				ID:      "allow-submit-edr",
				Tool:    "submit_edr_query",
				Targets: []string{"server01.example.com"},
				Action:  "allow",
			},
		},
	})
	e := New(p)

	got := e.Evaluate(Call{Tool: "submit_edr_query", Target: "server01.example.com"})
	if got != DecisionAllow {
		t.Fatalf("want DecisionAllow, got %v", got)
	}
}

// TestEngine_DenyOnMiss — no rule matches yields Deny (Plan U3).
// Covers AE2 (read action with allowlist miss).
func TestEngine_DenyOnMiss(t *testing.T) {
	p := mustCompile(t, &config.Policy{
		DefaultAction: "deny",
		Rules: []config.Rule{
			{
				ID:      "allow-submit-edr",
				Tool:    "submit_edr_query",
				Targets: []string{"*.example.com"},
				Action:  "allow",
			},
		},
	})
	e := New(p)

	got := e.Evaluate(Call{Tool: "submit_edr_query", Target: "server02.other.org"})
	if got != DecisionDeny {
		t.Fatalf("want DecisionDeny, got %v", got)
	}
}

// TestEngine_DestructiveVerb_AlwaysTriggers — even with no explicit
// rule, a destructive-verb tool requires approval (Plan U3, R7).
func TestEngine_DestructiveVerb_AlwaysTriggers(t *testing.T) {
	// Policy explicitly contains NO rules; the destructive-verb
	// catch-all is the only thing that fires.
	p := mustCompile(t, &config.Policy{
		DefaultAction: "deny",
		Rules:         nil,
	})
	e := New(p)

	got := e.Evaluate(Call{Tool: "delete_file", Target: "anywhere"})
	if got != DecisionRequireApproval {
		t.Fatalf("want DecisionRequireApproval, got %v", got)
	}
}

// TestEngine_GlobMatch — `*.example.com` matches `server01.example.com`
// (Plan U3). Covers AE1 (read action with allowlist match).
func TestEngine_GlobMatch(t *testing.T) {
	p := mustCompile(t, &config.Policy{
		DefaultAction: "deny",
		Rules: []config.Rule{
			{
				ID:      "allow-edr-glob",
				Tool:    "submit_edr_query",
				Targets: []string{"*.example.com"},
				Action:  "allow",
			},
		},
	})
	e := New(p)

	got := e.Evaluate(Call{Tool: "submit_edr_query", Target: "server01.example.com"})
	if got != DecisionAllow {
		t.Fatalf("want DecisionAllow, got %v", got)
	}

	// Sanity: a non-matching host is still denied.
	got2 := e.Evaluate(Call{Tool: "submit_edr_query", Target: "server02.other.org"})
	if got2 != DecisionDeny {
		t.Fatalf("non-matching host: want DecisionDeny, got %v", got2)
	}
}

// TestEngine_AtomicSwap — concurrent reads during a swap do not
// deadlock and post-swap reads see the new policy (Plan U3, KTD3).
//
// The test runs many reader goroutines while a single goroutine
// swaps the policy. Every Evaluate call must complete without
// panic and must return a result consistent with EITHER the
// pre-swap policy OR the post-swap policy — never a mix.
//
// This is the property the atomic.Pointer buys us; if the
// implementation regressed to a bare pointer with no atomic,
// `go test -race` would flag the data race.
func TestEngine_AtomicSwap(t *testing.T) {
	preSwap := mustCompile(t, &config.Policy{
		DefaultAction: "deny",
		Rules: []config.Rule{
			{ID: "allow-pre", Tool: "tool_a", Action: "allow"},
		},
	})
	postSwap := mustCompile(t, &config.Policy{
		DefaultAction: "deny",
		Rules: []config.Rule{
			{ID: "allow-post", Tool: "tool_a", Action: "deny"},
		},
	})

	e := New(preSwap)

	const (
		readers           = 8
		readsPerGoroutine = 200
	)
	var wg sync.WaitGroup
	wg.Add(readers)

	// Start readers.
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < readsPerGoroutine; j++ {
				// Every call must return one of the two valid
				// decisions — never crash, never return DecisionUnset.
				d := e.Evaluate(Call{Tool: "tool_a"})
				if d != DecisionAllow && d != DecisionDeny {
					t.Errorf("Evaluate returned unexpected decision %v", d)
					return
				}
			}
		}()
	}

	// Swap policy under load. This is the operation that would race
	// without atomic.Pointer; the test verifies no reader sees a
	// half-swapped state.
	e.Update(postSwap)

	// One more post-swap read to confirm the new policy is live.
	if got := e.Evaluate(Call{Tool: "tool_a"}); got != DecisionDeny {
		t.Fatalf("post-swap: want DecisionDeny, got %v", got)
	}

	wg.Wait()

	// Sanity: Current() reports the post-swap policy.
	if got := e.Current(); got != postSwap {
		t.Fatalf("Current() did not return post-swap policy")
	}
}

// TestEngine_CatchAllDestructive — a non-catalog tool with the
// `truncate_table` verb is intercepted by the catch-all (Plan U3,
// R7, AE4).
func TestEngine_CatchAllDestructive(t *testing.T) {
	// The custom tool is NOT in any rule. Only the catch-all
	// destructive-verb gate should intercept it.
	p := mustCompile(t, &config.Policy{
		DefaultAction: "allow", // deliberately not "deny": if the
		// catch-all failed to fire, Evaluate would return
		// DecisionAllow and the test would catch the regression.
		Rules: []config.Rule{
			{
				ID:     "allow-isolate",
				Tool:   "isolate_endpoint",
				Action: "require_approval",
			},
		},
	})
	e := New(p)

	got := e.Evaluate(Call{Tool: "truncate_table", Target: "production_db"})
	if got != DecisionRequireApproval {
		t.Fatalf("want DecisionRequireApproval, got %v", got)
	}
}

// TestEngine_CatchAllInvariant — even if a buggy loader mutates
// CatchAll.Decision to anything other than DecisionRequireApproval,
// the destructive-verb gate MUST still fire. This is the regression
// test for the fail-open state-drift flagged in the security
// review: the gate is hard-coded in Evaluate, not a switch on
// CatchAll.Decision.
func TestEngine_CatchAllInvariant(t *testing.T) {
	p := mustCompile(t, &config.Policy{
		DefaultAction: "allow",
		Rules:         nil,
	})
	// Simulate a buggy loader that flipped CatchAll.Decision.
	p.CatchAll.Decision = DecisionAllow
	e := New(p)

	// truncate_table MUST still require approval.
	got := e.Evaluate(Call{Tool: "truncate_table"})
	if got != DecisionRequireApproval {
		t.Fatalf("CatchAll.Decision mutation leaked: got %v, want DecisionRequireApproval", got)
	}
	// Even DecisionDeny must not let the gate disable.
	p.CatchAll.Decision = DecisionDeny
	got = e.Evaluate(Call{Tool: "drop_table"})
	if got != DecisionRequireApproval {
		t.Fatalf("CatchAll.Decision=DecisionDeny leaked: got %v, want DecisionRequireApproval", got)
	}
}

// TestEngine_RejectsNonASCIIToolName — defense against homoglyph
// attacks. A tool name containing non-ASCII letters (e.g. Cyrillic
// 'е' in "Dеlete_user") MUST be rejected regardless of what rules
// match it. Without this check, an operator's wildcard allow rule
// (e.g. `delete_*`) would let a homoglyph attack through. NFKC
// does not fold cross-script homoglyphs, so the only safe defense
// is to require printable-ASCII tool names.
func TestEngine_RejectsNonASCIIToolName(t *testing.T) {
	// Even with default_action=allow and an explicit wildcard
	// allow rule that would otherwise match, the homoglyph attack
	// must be denied.
	p := mustCompile(t, &config.Policy{
		DefaultAction: "allow",
		Rules: []config.Rule{
			{
				ID:     "allow-delete-wildcard",
				Tool:   "delete_*",
				Action: "allow",
			},
		},
	})
	e := New(p)

	cases := []struct {
		name string
		tool string
	}{
		{"cyrillic_e", "Dеlete_user"},          // Cyrillic 'е' (U+0435)
		{"cyrillic_e_in_truncate", "truncаte"}, // Cyrillic 'а' (U+0430)
		{"greek_alpha", "α"},                   // pure Greek
		{"cjk", "隔离_endpoint"},                 // CJK
		{"space_in_tool", "delete user"},       // space (not printable for our purposes)
		{"empty_tool", ""},                     // empty is malformed
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := e.Evaluate(Call{Tool: tc.tool})
			if got != DecisionDeny {
				t.Errorf("Evaluate(Tool=%q) = %v, want DecisionDeny (homoglyph defense)", tc.tool, got)
			}
		})
	}
}

// TestEngine_AllowsLegitimateASCIITools — regression test that
// the ASCII-only invariant does not over-reject legitimate ASCII
// tool names that include numbers or unusual separators. The catch-
// all rule uses "**" (matches across segment separators) since
// gobwas/glob treats "*" as single-segment only.
func TestEngine_AllowsLegitimateASCIITools(t *testing.T) {
	p := mustCompile(t, &config.Policy{
		DefaultAction: "deny",
		Rules: []config.Rule{
			{
				ID:     "allow-readonly",
				Tool:   "**",
				Action: "allow",
			},
		},
	})
	e := New(p)

	cases := []string{
		"submit_edr_query",
		"isolate_endpoint",
		"block-user-account", // kebab-case
		"rotate.api.key",     // dots (covered by **)
		"tool123",            // digits
		"x",                  // single char
		"FOO_BAR",            // uppercase
	}
	for _, tool := range cases {
		t.Run(tool, func(t *testing.T) {
			got := e.Evaluate(Call{Tool: tool})
			if got != DecisionAllow {
				t.Errorf("Evaluate(Tool=%q) = %v, want DecisionAllow", tool, got)
			}
		})
	}
}

// TestEngine_DefaultDeny_DefaultPolicy — without a configured rule
// the proxy default-denies per Plan R1.
func TestEngine_DefaultDeny_DefaultPolicy(t *testing.T) {
	p := mustCompile(t, &config.Policy{
		DefaultAction: "deny",
		Rules:         nil,
	})
	e := New(p)

	// A non-destructive tool with no matching rule must deny.
	if got := e.Evaluate(Call{Tool: "submit_edr_query", Target: "x"}); got != DecisionDeny {
		t.Fatalf("want DecisionDeny, got %v", got)
	}
}

// TestEngine_ExactWinsOverGlob — when both an exact-tool rule and a
// glob-tool rule could match, the exact one wins (Plan KTD3:
// specificity ordering at load time).
func TestEngine_ExactWinsOverGlob(t *testing.T) {
	p := mustCompile(t, &config.Policy{
		DefaultAction: "deny",
		Rules: []config.Rule{
			// Glob rule first on disk; engine must still prefer
			// the exact rule below it.
			{ID: "glob-deny", Tool: "submit_*", Action: "deny"},
			{ID: "exact-allow", Tool: "submit_edr_query", Action: "allow"},
		},
	})
	e := New(p)

	if got := e.Evaluate(Call{Tool: "submit_edr_query"}); got != DecisionAllow {
		t.Fatalf("exact rule should win over glob: got %v", got)
	}

	// And a different submit_* tool still falls through to the
	// glob rule.
	if got := e.Evaluate(Call{Tool: "submit_other"}); got != DecisionDeny {
		t.Fatalf("glob rule should match other submit_*: got %v", got)
	}
}

// TestEngine_NewDenyByDefault — empty engine denies everything that
// is not a destructive verb.
func TestEngine_NewDenyByDefault(t *testing.T) {
	e := NewDenyByDefault()

	if got := e.Evaluate(Call{Tool: "submit_edr_query"}); got != DecisionDeny {
		t.Fatalf("want DecisionDeny, got %v", got)
	}
	if got := e.Evaluate(Call{Tool: "delete_thing"}); got != DecisionRequireApproval {
		t.Fatalf("destructive tool: want DecisionRequireApproval, got %v", got)
	}
}

// TestEngine_UpdateNilFallsBack — passing nil to Update restores
// the deny-by-default policy rather than leaving the engine with a
// nil pointer.
func TestEngine_UpdateNilFallsBack(t *testing.T) {
	e := New(mustCompile(t, &config.Policy{DefaultAction: "allow"}))
	e.Update(nil)

	if got := e.Evaluate(Call{Tool: "submit_edr_query"}); got != DecisionDeny {
		t.Fatalf("nil swap should restore deny-by-default, got %v", got)
	}
}

// TestCompile_RejectsBadDefault — Compile refuses unknown default
// actions. This is the "broken policy file must never allow by
// default" cardinal rule.
func TestCompile_RejectsBadDefault(t *testing.T) {
	_, err := Compile(&config.Policy{DefaultAction: "bogus"})
	if err == nil {
		t.Fatalf("expected error for bogus default_action")
	}
}

// TestCompile_RejectsBadRuleAction — unknown per-rule actions fail
// to compile.
func TestCompile_RejectsBadRuleAction(t *testing.T) {
	_, err := Compile(&config.Policy{
		DefaultAction: "deny",
		Rules: []config.Rule{
			{ID: "bad", Tool: "x", Action: "explode"},
		},
	})
	if err == nil {
		t.Fatalf("expected error for bad rule action")
	}
}

// TestCompile_RejectsBadGlob — a syntactically invalid glob pattern
// fails to compile rather than silently skipping the rule.
func TestCompile_RejectsBadGlob(t *testing.T) {
	// gobwas/glob accepts most malformed input; the safe way to
	// force a compile error is an unterminated character class.
	_, err := Compile(&config.Policy{
		DefaultAction: "deny",
		Rules: []config.Rule{
			{ID: "bad", Tool: "submit_[", Action: "allow"},
		},
	})
	if err == nil {
		t.Fatalf("expected error for malformed glob")
	}
}
