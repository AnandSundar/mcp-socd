package policy

import "strings"

// IsGlob reports whether pattern contains any glob metacharacter
// ('*', '?', '[', '{'). An empty pattern is not a glob.
//
// This is the cheapest possible specificity check: a literal string
// has zero metacharacters, anything else is treated as a glob. The
// gobwas/glob library does not expose a public API for this so we
// match its documented metacharacter set directly.
func IsGlob(pattern string) bool {
	return strings.ContainsAny(pattern, globMetaChars)
}
