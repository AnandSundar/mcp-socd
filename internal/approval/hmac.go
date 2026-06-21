// HMAC-bound approval token. See Plan §KTD8 and §U6 "HMAC-bound
// request token".
//
// # Threat model
//
// A malicious tool call could try to nudge an unrelated approval
// prompt to a positive answer by repeating a token the operator has
// seen before. The token here signs the request id with a
// server-side secret so a token that worked for one request is
// worthless for any other. The operator sees an 8-character prefix
// of the token; the full token must be presented to approve.
//
// # Format
//
// Token = base64url(HMAC-SHA256(secret, requestID))
//
// No timestamp is included because the workflow's outer timeout is
// the only validity window: a token older than the workflow timeout
// is by construction no longer interesting, and adding a separate
// expiration would just give an attacker a clock-skew attack.
//
// # Lifecycle
//
//   1. Workflow.Approve calls SignToken(req.RequestID, w.secret) and
//      stores the result on req.Token.
//   2. The terminal channel (or future Slack channel) renders the
//      8-char prefix to the operator.
//   3. The operator types "y <full-token>" or "n <full-token>".
//   4. The channel calls VerifyToken(req.RequestID, presented,
//      w.secret). On mismatch it refuses to accept the response.

package approval

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// TokenPrefixLen is the number of base64url characters of a token
// that is rendered to the operator for visual confirmation. Short
// enough to read; long enough that two distinct tokens in a row
// are visually distinguishable.
const TokenPrefixLen = 8

// ErrTokenMismatch is returned by VerifyToken when the presented
// token does not match the expected signature. Channels should treat
// this as a definitive deny (with audit) rather than retrying: the
// right answer is that the operator was looking at a different
// approval prompt.
var ErrTokenMismatch = errors.New("approval: token mismatch")

// SignToken returns the base64url-encoded HMAC-SHA256 of requestID
// under secret. The same requestID + secret pair always produces
// the same token; distinct requestIDs produce unrelated tokens
// (HMAC is deterministic). Returns an empty string when either
// argument is empty so callers can fail loud rather than silently
// minting a constant token.
func SignToken(requestID string, secret []byte) string {
	if requestID == "" || len(secret) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, secret)
	// hmac.Hash.Write never returns an error.
	_, _ = mac.Write([]byte(requestID))
	sum := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum)
}

// VerifyToken reports whether presented is the expected token for
// requestID under secret. The comparison is constant-time so the
// caller cannot be used as a side-channel oracle.
//
// A presented token of the wrong length is rejected with
// ErrTokenMismatch (never with a different error) so callers can
// collapse both "wrong token" and "no token" into one branch.
func VerifyToken(requestID, presented string, secret []byte) error {
	expected := SignToken(requestID, secret)
	if expected == "" {
		// Should not happen if the workflow constructed the token;
		// a missing requestID here means the caller has a bug.
		return fmt.Errorf("approval: cannot verify token: empty requestID or secret")
	}
	// hmac.Equal is constant-time and length-mismatch safe.
	if !hmac.Equal([]byte(expected), []byte(presented)) {
		return ErrTokenMismatch
	}
	return nil
}

// TokenPrefix returns the first TokenPrefixLen characters of a
// token, suitable for display in an operator prompt. Returns ""
// when the token is too short to safely show a prefix (which would
// imply a malformed token anyway).
func TokenPrefix(token string) string {
	if len(token) < TokenPrefixLen {
		return ""
	}
	return token[:TokenPrefixLen]
}
