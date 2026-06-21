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
