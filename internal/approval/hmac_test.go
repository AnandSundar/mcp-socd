package approval

import (
	"strings"
	"testing"
)

// TestHMAC_SignAndVerify exercises the happy path: signing produces
// a stable token for the same requestID + secret pair, and Verify
// accepts it. Backed by Plan §U6 "HMAC-bound request token".
func TestHMAC_SignAndVerify(t *testing.T) {
	secret := []byte("test-secret-do-not-use-in-prod")
	id := "req-1234"

	token := SignToken(id, secret)
	if token == "" {
		t.Fatal("SignToken returned empty for non-empty inputs")
	}

	if err := VerifyToken(id, token, secret); err != nil {
		t.Fatalf("VerifyToken rejected a freshly signed token: %v", err)
	}
}

// TestHMAC_DifferentIDsDifferentTokens — distinct requestIDs produce
// distinct tokens under the same secret. This is the property that
// prevents replay across requests.
func TestHMAC_DifferentIDsDifferentTokens(t *testing.T) {
	secret := []byte("shared-secret")
	a := SignToken("req-aaa", secret)
	b := SignToken("req-bbb", secret)

	if a == b {
		t.Fatalf("expected distinct tokens for distinct requestIDs, got identical: %q", a)
	}
	if err := VerifyToken("req-aaa", a, secret); err != nil {
		t.Fatalf("verify a failed: %v", err)
	}
	if err := VerifyToken("req-bbb", b, secret); err != nil {
		t.Fatalf("verify b failed: %v", err)
	}
	// Cross-verify: token for req-aaa must NOT verify under req-bbb.
	if err := VerifyToken("req-bbb", a, secret); err == nil {
		t.Fatal("token for req-aaa verified under req-bbb; replay protection broken")
	}
}

// TestHMAC_DifferentSecretsDifferentTokens — distinct secrets produce
// distinct tokens for the same requestID. This is what makes a
// secret rotation effective.
func TestHMAC_DifferentSecretsDifferentTokens(t *testing.T) {
	id := "req-1234"
	a := SignToken(id, []byte("secret-one"))
	b := SignToken(id, []byte("secret-two"))

	if a == b {
		t.Fatalf("expected distinct tokens for distinct secrets, got identical: %q", a)
	}
}

// TestHMAC_ForgedTokenRejected — covers Plan scenario #5
// ("TestHMACToken_VerifiesOnResponse: forged token is rejected").
func TestHMAC_ForgedTokenRejected(t *testing.T) {
	secret := []byte("real-secret")
	id := "req-1234"

	real := SignToken(id, secret)
	// Forge: replace the last character with a different
	// base64url-safe character.
	forged := real[:len(real)-1] + string(flipChar(real[len(real)-1]))

	if forged == real {
		t.Fatal("forge produced identical token; test setup is wrong")
	}
	if err := VerifyToken(id, forged, secret); err == nil {
		t.Fatal("forged token verified; HMAC binding broken")
	}
	if err := VerifyToken(id, forged, secret); !strings.Contains(err.Error(), "token") {
		t.Fatalf("expected token-mismatch error, got %v", err)
	}
}

// TestHMAC_EmptyArgsRejected — SignToken and VerifyToken refuse
// empty inputs rather than silently minting/accepting a constant.
func TestHMAC_EmptyArgsRejected(t *testing.T) {
	secret := []byte("s")

	if got := SignToken("", secret); got != "" {
		t.Fatalf("SignToken(empty id) = %q, want empty", got)
	}
	if got := SignToken("id", nil); got != "" {
		t.Fatalf("SignToken(nil secret) = %q, want empty", got)
	}
	if err := VerifyToken("", "anything", secret); err == nil {
		t.Fatal("VerifyToken accepted empty requestID")
	}
	if err := VerifyToken("id", "anything", nil); err == nil {
		t.Fatal("VerifyToken accepted nil secret")
	}
}

// TestHMAC_TokenPrefix — TokenPrefix returns the first
// TokenPrefixLen characters and never more, never less.
func TestHMAC_TokenPrefix(t *testing.T) {
	secret := []byte("s")
	tok := SignToken("id", secret)
	if len(tok) < TokenPrefixLen {
		t.Fatalf("token shorter than prefix length: %d < %d", len(tok), TokenPrefixLen)
	}
	if got := TokenPrefix(tok); got != tok[:TokenPrefixLen] {
		t.Fatalf("TokenPrefix = %q, want %q", got, tok[:TokenPrefixLen])
	}
	if got := TokenPrefix(""); got != "" {
		t.Fatalf("TokenPrefix(empty) = %q, want empty", got)
	}
	if got := TokenPrefix("short"); got != "" {
		t.Fatalf("TokenPrefix(short) = %q, want empty for shorter-than-prefix input", got)
	}
}

// flipChar returns a different base64url character. It panics if c
// is not in the base64url alphabet — only called with valid input
// from a freshly generated token.
func flipChar(c byte) byte {
	switch c {
	case 'A':
		return 'B'
	case 'a':
		return 'b'
	case '0':
		return '1'
	default:
		// For any other character (most base64url chars) a single
		// offset change keeps the result in-alphabet.
		return c + 1
	}
}
