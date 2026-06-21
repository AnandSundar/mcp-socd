package policy

import "strings"

// DestructiveVerbs is the canonical list of action verbs the proxy
// intercepts regardless of catalog membership, per Plan R7. The list
// matches the origin document exactly:
//
//	delete, drop, truncate, revoke, disable, wipe, purge
//
// The verbs are stored lowercase and matched case-insensitively,
// because MCP tool names are case-sensitive identifiers but the
// destructive-verb check is a safety net that must not be defeated
// by capitalization tricks ("Delete_File" should still be caught).
var DestructiveVerbs = []string{
	"delete",
	"drop",
	"truncate",
	"revoke",
	"disable",
	"wipe",
	"purge",
}

// verbSeparator is the rune set we treat as a word boundary when
// scanning tool names. Snake_case and kebab-case are both common in
// MCP tool naming; we do not want "deletedata" to match the verb
// "delete" (substring false positive) but we do want
// "delete_data" and "delete-data" to match.
//
// The set covers underscores, dashes, dots, and whitespace.
const verbSeparator = "_-. \t"

// IsDestructiveTool reports whether tool contains any of the
// destructive verbs (Plan R7) at a word boundary. Substring matches
// inside larger identifiers are not considered destructive: the
// gate is meant to catch known-dangerous action patterns, not to
// flag every tool that happens to contain the letters "del".
//
// Matching is case-insensitive. Returns true if any verb is found
// preceded by either the start of the string or a non-separator
// rune AND followed by either the end of the string or a
// non-separator rune.
//
// Examples:
//
//	IsDestructiveTool("delete_file")   -> true  (delete + "_" boundary)
//	IsDestructiveTool("DELETE_file")   -> true  (case-insensitive)
//	IsDestructiveTool("truncate")      -> true  (exact match)
//	IsDestructiveTool("truncate-table") -> true
//	IsDestructiveTool("deletedata")    -> false (no boundary after delete)
//	IsDestructiveTool("submit_edr_query") -> false
//	IsDestructiveTool("isolate_endpoint") -> false
func IsDestructiveTool(tool string) bool {
	if tool == "" {
		return false
	}
	lower := strings.ToLower(tool)
	for _, verb := range DestructiveVerbs {
		if containsWord(lower, verb) {
			return true
		}
	}
	return false
}

// DestructiveVerbInTool returns the first destructive verb found in
// tool (lowercased), or "" if none. Exposed for audit metadata so
// post-hoc analysts can see exactly which verb triggered the gate.
func DestructiveVerbInTool(tool string) string {
	if tool == "" {
		return ""
	}
	lower := strings.ToLower(tool)
	for _, verb := range DestructiveVerbs {
		if containsWord(lower, verb) {
			return verb
		}
	}
	return ""
}

// containsWord reports whether needle appears in haystack at a
// word boundary. Both are expected to be lowercase.
//
// A match is at a word boundary when the rune immediately before
// the match is either the start of the string or a separator
// ("_-. \t"), AND the rune immediately after the match is either
// the end of the string or a separator. This matches the common
// snake_case and kebab-case MCP tool naming conventions without
// false-positive substring matches like "deletedata".
func containsWord(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	idx := 0
	for {
		j := strings.Index(haystack[idx:], needle)
		if j < 0 {
			return false
		}
		start := idx + j
		end := start + len(needle)

		leftOK := start == 0 || isSeparator(rune(haystack[start-1]))
		rightOK := end == len(haystack) || isSeparator(rune(haystack[end]))

		if leftOK && rightOK {
			return true
		}
		idx = start + 1
	}
}

// isSeparator reports whether r is a word-boundary rune for the
// purposes of verb detection.
func isSeparator(r rune) bool {
	return strings.ContainsRune(verbSeparator, r)
}
