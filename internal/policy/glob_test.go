package policy

import (
	"testing"

	"mcp-socd/internal/config"
)

// TestIsGlob — the cheap metacharacter check used to decide whether
// a pattern needs to be compiled by gobwas/glob or can be matched
// as a literal.
func TestIsGlob(t *testing.T) {
	cases := []struct {
		pattern string
		want    bool
	}{
		{"", false},
		{"submit_edr_query", false},
		{"server01.example.com", false},
		{"*", true},
		{"*.example.com", true},
		{"submit_*", true},
		{"?", true},
		{"a?b", true},
		{"[abc]", true},
		{"{a,b}", true},
		{"a*b", true},
	}
	for _, tc := range cases {
		got := IsGlob(tc.pattern)
		if got != tc.want {
			t.Errorf("IsGlob(%q) = %v, want %v", tc.pattern, got, tc.want)
		}
	}
}

// TestGlobMatch_CompiledRule — verify the gobwas/glob compile path
// produces a working matcher that respects dot-separated segments
// (the '.' separator we pass to glob.Compile).
func TestGlobMatch_CompiledRule(t *testing.T) {
	r := config.Rule{
		ID:      "g",
		Tool:    "submit_*",
		Targets: []string{"*.example.com"},
		Action:  "allow",
	}
	cr, err := compileRule(&r)
	if err != nil {
		t.Fatalf("compileRule: %v", err)
	}

	// Glob target matches.
	if !cr.TargetGlobs[0].Match("server01.example.com") {
		t.Errorf("expected *.example.com to match server01.example.com")
	}
	if cr.TargetGlobs[0].Match("example.com.evil.test") {
		t.Errorf("*.example.com should NOT match across dots (separator='.')")
	}

	// Glob tool matches.
	if !cr.ToolGlob.Match("submit_edr_query") {
		t.Errorf("expected submit_* to match submit_edr_query")
	}
	if cr.ToolGlob.Match("read_submit") {
		t.Errorf("submit_* should NOT match read_submit (prefix, not suffix)")
	}
}

// TestCompile_PreservesLiteralTargets — a literal (non-glob) target
// still produces a working matcher (we compile it through glob.Glob
// for uniformity on the hot path).
func TestCompile_PreservesLiteralTargets(t *testing.T) {
	cp := &config.Policy{
		DefaultAction: "deny",
		Rules: []config.Rule{
			{
				ID:      "literal",
				Tool:    "submit_edr_query",
				Targets: []string{"server01.example.com"},
				Action:  "allow",
			},
		},
	}
	p, err := Compile(cp)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	e := New(p)

	if got := e.Evaluate(Call{Tool: "submit_edr_query", Target: "server01.example.com"}); got != DecisionAllow {
		t.Errorf("literal target match: want Allow, got %v", got)
	}
	if got := e.Evaluate(Call{Tool: "submit_edr_query", Target: "server02.example.com"}); got != DecisionDeny {
		t.Errorf("literal target miss: want Deny, got %v", got)
	}
}
