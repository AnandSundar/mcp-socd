package policy

import "testing"

// TestDestructiveVerbs_ListComplete — the canonical verb list per
// Plan R7 contains exactly the seven verbs called out in the
// origin document. Adding a verb is a security-relevant change and
// must be intentional; this test fails loudly if anyone touches
// the list.
func TestDestructiveVerbs_ListComplete(t *testing.T) {
	want := []string{"delete", "drop", "truncate", "revoke", "disable", "wipe", "purge"}
	if len(DestructiveVerbs) != len(want) {
		t.Fatalf("DestructiveVerbs length changed: got %d, want %d (%v)",
			len(DestructiveVerbs), len(want), DestructiveVerbs)
	}
	for i, v := range want {
		if DestructiveVerbs[i] != v {
			t.Errorf("DestructiveVerbs[%d] = %q, want %q", i, DestructiveVerbs[i], v)
		}
	}
}

// TestIsDestructiveTool — boundary-aware verb detection. The gate
// must catch known-dangerous patterns without false-positive
// substring matches.
func TestIsDestructiveTool(t *testing.T) {
	cases := []struct {
		tool string
		want bool
	}{
		// Should fire.
		{"delete_file", true},
		{"drop_table", true},
		{"truncate", true},
		{"revoke_key", true},
		{"disable_user", true},
		{"wipe_disk", true},
		{"purge_cache", true},
		{"delete-data", true},
		{"delete.data", true},
		{"DELETE_FILE", true},    // case-insensitive
		{"Truncate_Table", true}, // snake_case at any boundary

		// Should NOT fire — the verb appears only as a substring
		// inside a larger identifier with no word boundary.
		{"deletedata", false},
		{"droptable", false},
		{"truncatedata", false},
		{"revokedata", false},
		{"disabledata", false},

		// Non-destructive tools.
		{"submit_edr_query", false},
		{"isolate_endpoint", false},
		{"block_user_account", false},
		{"rotate_api_key", false},
		{"enrich_ioc", false},
		{"", false},
	}
	for _, tc := range cases {
		got := IsDestructiveTool(tc.tool)
		if got != tc.want {
			t.Errorf("IsDestructiveTool(%q) = %v, want %v", tc.tool, got, tc.want)
		}
	}
}

// TestDestructiveVerbInTool — the verb returned for audit metadata
// is the original lowercase verb, not the original-case identifier.
func TestDestructiveVerbInTool(t *testing.T) {
	cases := []struct {
		tool string
		want string
	}{
		{"delete_file", "delete"},
		{"DROP_TABLE", "drop"},
		{"Truncate_Table", "truncate"},
		{"isolate_endpoint", ""},
		{"", ""},
	}
	for _, tc := range cases {
		got := DestructiveVerbInTool(tc.tool)
		if got != tc.want {
			t.Errorf("DestructiveVerbInTool(%q) = %q, want %q", tc.tool, got, tc.want)
		}
	}
}

// TestIsDestructiveTool_Homoglyph — homoglyph attacks that use
// non-ASCII letters to spell a destructive verb (e.g. Cyrillic 'е'
// instead of Latin 'e' in "Dеlete_file") are NOT detected by this
// gate. The defense is at a separate layer (Engine.Evaluate's
// isASCIIPrintable check): non-ASCII tool names are rejected
// outright, which triggers DecisionDeny regardless of any matching
// glob rule. NFKC normalization does NOT fold cross-script
// homoglyphs; that requires a Unicode confusables table. Our
// chosen defense: ASCII-only tool names. This test pins the
// contract — IsDestructiveTool returns false for non-ASCII inputs
// (treated as unknown), and the engine-level invariant is
// tested separately in policy_test.go.
func TestIsDestructiveTool_Homoglyph(t *testing.T) {
	cases := []struct {
		name string
		tool string
		want bool
	}{
		// All non-ASCII: not recognized as a destructive verb.
		// The defense is at the engine layer, not here.
		{"cyrillic_e_in_delete", "Dеlete_file", false},
		{"cyrillic_e_in_truncate", "truncаte_table", false},
		{"greek_alpha_in_wipe", "wαpe_disk", false},
		{"cyrillic_in_safe_word", "submіt_edr_query", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsDestructiveTool(tc.tool)
			if got != tc.want {
				t.Errorf("IsDestructiveTool(%q) = %v, want %v", tc.tool, got, tc.want)
			}
		})
	}
}

// TestIsDestructiveTool_MultibyteBoundary — word-boundary checks
// operate on runes, so the function is correct for multi-byte
// UTF-8 sequences within the ASCII subset. (Non-ASCII inputs are
// rejected at the engine layer; see TestIsDestructiveTool_Homoglyph
// and the policy_test.go engine-level ASCII check.) The test
// inputs here use only printable ASCII to verify the rune-level
// scan does not regress on legitimate edge cases.
func TestIsDestructiveTool_MultibyteBoundary(t *testing.T) {
	// These are all-ASCII inputs that exercise the rune-level
	// scanning logic. The previous bug (cast raw bytes to runes)
	// was a parser differential; the new code converts to runes
	// once and operates on rune indices.
	cases := []struct {
		name string
		tool string
		want bool
	}{
		// Pure ASCII — these must keep working.
		{"single_verb", "delete", true},
		{"verb_underscore_target", "delete_file", true},
		{"verb_dash_target", "delete-file", true},
		{"verb_dot_target", "delete.file", true},
		{"uppercase_verb", "DELETE", true},

		// Substring without boundary — these must keep NOT firing.
		{"substring_no_boundary", "deletedata", false},
		{"prefix_substring", "deletefile", false},

		// Edge cases.
		{"empty", "", false},
		{"single_char_verb", "d", false}, // too short to be a verb
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsDestructiveTool(tc.tool)
			if got != tc.want {
				t.Errorf("IsDestructiveTool(%q) = %v, want %v", tc.tool, got, tc.want)
			}
		})
	}
}
