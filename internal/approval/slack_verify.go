// Slack signing-secret verification for HTTP-mode payloads.
// See Plan §KTD7 "5-minute replay window".
//
// In production the proxy runs over Socket Mode, where the
// slack-go/socketmode library verifies signatures internally
// (it owns the signing secret and the timestamp check). This
// helper exists for two reasons:
//
//  1. Tests can exercise the verification logic without
//     standing up a real Slack workspace.
//  2. The HTTP-mode fallback path (a future public-webhook
//     mode, if added) needs an explicit verifier that takes
//     the raw request body and headers.
//
// # Scheme (per https://api.slack.com/authentication/verifying-requests-from-slack)
//
//	base = "v0:" + X-Slack-Request-Timestamp + ":" + raw_body
//	expected = "v0=" + hex(HMAC-SHA256(signing_secret, base))
//
// Compare expected to X-Slack-Signature in constant time. The
// timestamp must be within ±5 minutes of wall-clock time;
// outside that window the request is rejected as a replay.

package approval

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// slackSignatureMaxClockSkew is the Plan §KTD7 replay window:
// 5 minutes. Larger than the typical network jitter budget
// (seconds) but small enough that a leaked payload is not
// replayable indefinitely.
const slackSignatureMaxClockSkew = 5 * time.Minute

// ErrSlackSignatureMismatch is returned by verifySlackSignature
// when the computed HMAC does not match the X-Slack-Signature
// header. Distinct from ErrTimestampSkew so callers (and tests)
// can distinguish a tampered payload from a stale one.
var ErrSlackSignatureMismatch = errors.New("approval: slack signature mismatch")

// ErrSlackTimestampSkew is returned when the
// X-Slack-Request-Timestamp header is older than the replay
// window (or otherwise unparseable). The body is not even
// considered — a stale timestamp is itself a rejection
// condition, regardless of whether the signature would have
// verified.
var ErrSlackTimestampSkew = errors.New("approval: slack timestamp outside replay window")

// verifySlackSignature checks that headers and body would have
// been produced by Slack holding signingSecret. Returns nil on
// success, ErrSlackSignatureMismatch on a bad signature,
// ErrSlackTimestampSkew on a stale timestamp.
//
// The signature is compared in constant time so a caller
// cannot use this function as a side-channel oracle for the
// signing secret.
//
// signingSecret is the per-app "Signing Secret" exposed in
// Slack's Basic Information page. It is the same secret used
// by Socket Mode for connection authentication.
//
// The X-Slack-Request-Timestamp header is interpreted as Unix
// seconds (Slack's wire format). A clock skew larger than
// slackSignatureMaxClockSkew rejects even a correctly-signed
// payload, on the principle that a stolen recent payload
// should not be replayable forever.
func verifySlackSignature(signingSecret string, headers http.Header, body []byte) error {
	if signingSecret == "" {
		return errors.New("approval: verifySlackSignature requires a non-empty signing secret")
	}

	sigHeader := headers.Get("X-Slack-Signature")
	if sigHeader == "" {
		return ErrSlackSignatureMismatch
	}
	if !strings.HasPrefix(sigHeader, "v0=") {
		// Slack's spec requires the v0= prefix; anything else
		// is malformed.
		return ErrSlackSignatureMismatch
	}
	presentedMAC, err := hex.DecodeString(strings.TrimPrefix(sigHeader, "v0="))
	if err != nil {
		return ErrSlackSignatureMismatch
	}

	tsHeader := headers.Get("X-Slack-Request-Timestamp")
	if tsHeader == "" {
		return ErrSlackTimestampSkew
	}
	tsInt, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return ErrSlackTimestampSkew
	}
	ts := time.Unix(tsInt, 0)
	if delta := time.Since(ts); delta > slackSignatureMaxClockSkew || delta < -slackSignatureMaxClockSkew {
		return ErrSlackTimestampSkew
	}

	// base = "v0:" + timestamp + ":" + raw body
	mac := hmac.New(sha256.New, []byte(signingSecret))
	mac.Write([]byte("v0:"))
	mac.Write([]byte(tsHeader))
	mac.Write([]byte(":"))
	mac.Write(body)
	expectedMAC := mac.Sum(nil)

	// hmac.Equal is constant-time and length-mismatch safe.
	if !hmac.Equal(expectedMAC, presentedMAC) {
		return ErrSlackSignatureMismatch
	}
	return nil
}