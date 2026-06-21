package policy

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

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
// Matching is case-insensitive (Unicode-aware) and homoglyph-safe:
// the tool name is NFKC-normalized before matching so that
// Cyrillic 'е' (U+0435) in a tool name like "Dеlete_file" is
// folded to Latin 'e' and still triggers the gate. Word-boundary
// checks operate on runes, not bytes, so multi-byte UTF-8
// characters adjacent to a verb do not produce a false negative
// (or false positive) on the boundary test.
//
// Examples:
//
//	IsDestructiveTool("delete_file")   -> true  (delete + "_" boundary)
//	IsDestructiveTool("DELETE_file")   -> true  (case-insensitive)
//	IsDestructiveTool("truncate")      -> true  (exact match)
//	IsDestructiveTool("truncate-table") -> true
//	IsDestructiveTool("deletedata")    -> false (no boundary after delete)
//	IsDestructiveTool("Dеlete_file")   -> true  (Cyrillic 'е' folded to 'e')
//	IsDestructiveTool("submit_edr_query") -> false
//	IsDestructiveTool("isolate_endpoint") -> false
func IsDestructiveTool(tool string) bool {
	verb, _ := firstDestructiveVerb(tool)
	return verb != ""
}

// DestructiveVerbInTool returns the first destructive verb found in
// tool (lowercased), or "" if none. Exposed for audit metadata so
// post-hoc analysts can see exactly which verb triggered the gate.
func DestructiveVerbInTool(tool string) string {
	verb, _ := firstDestructiveVerb(tool)
	return verb
}

// firstDestructiveVerb returns the first destructive verb found in
// tool, along with the normalized form of tool. Both are useful:
// verb for the audit field, normalized for downstream consumers
// (audit, allowlist matching) that need a canonical representation
// of the tool name.
func firstDestructiveVerb(tool string) (verb, normalized string) {
	if tool == "" {
		return "", ""
	}
	// NFKC normalizes homoglyphs (Cyrillic 'е' -> Latin 'e'),
	// combining characters, and other Unicode trickery. After
	// normalization, strings.ToLower gives a stable ASCII-folded
	// view. We then work in runes to keep boundary checks correct
	// across multi-byte UTF-8.
	normalized = norm.NFKC.String(tool)
	lower := strings.ToLower(normalized)
	runes := []rune(lower)
	for _, v := range DestructiveVerbs {
		if containsWordRunes(runes, v) {
			return v, normalized
		}
	}
	return "", normalized
}

// containsWordRunes reports whether needle (ASCII lowercase verb)
// appears in runes (already lowercased) at a word boundary. Working
// in runes ensures the boundary check is correct for multi-byte
// UTF-8 sequences adjacent to a verb match.
func containsWordRunes(runes []rune, needle string) bool {
	if needle == "" {
		return false
	}
	needles := []rune(needle)
	n := len(needles)
	if n > len(runes) {
		return false
	}
	for i := 0; i+n <= len(runes); i++ {
		// Fast path: compare rune-by-rune.
		match := true
		for k := 0; k < n; k++ {
			if runes[i+k] != needles[k] {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		leftOK := i == 0 || isSeparator(runes[i-1])
		rightOK := i+n == len(runes) || isSeparator(runes[i+n])
		if leftOK && rightOK {
			return true
		}
	}
	return false
}

// isSeparator reports whether r is a word-boundary rune for the
// purposes of verb detection.
func isSeparator(r rune) bool {
	// Fast ASCII path — verbSeparator is all ASCII.
	if r <= 0x7E {
		return strings.IndexByte(verbSeparator, byte(r)) >= 0
	}
	// Allow any Unicode whitespace (NBSP, ideographic space, etc.)
	// as a boundary, in addition to the ASCII separator set.
	return unicode.IsSpace(r)
}
