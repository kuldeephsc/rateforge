// Package security implements input validation and small cryptographic
// helpers shared across Sentinel (FR10, STRIDE controls T1-T8 from
// design.md section 6).
package security

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// apiKeyPattern enforces the spec's API key charset: alphanumeric plus
// underscore/dash, 1-128 characters. The same pattern is reused for tier
// names (with their own length cap) since both are used as scheduler-id
// path components, where a stray '|' would be ambiguous.
var apiKeyPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

// tierPattern is slightly more permissive on length (tiers are
// operator-defined, not client-supplied at scale) but uses the same safe
// charset.
var tierPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// ErrInvalidAPIKey is returned by ValidateAPIKey for malformed keys.
var ErrInvalidAPIKey = errors.New("invalid api key: must match ^[a-zA-Z0-9_-]{1,128}$")

// ErrInvalidTier is returned by ValidateTier for malformed tier names.
var ErrInvalidTier = errors.New("invalid tier name: must match ^[a-zA-Z0-9_-]{1,64}$")

// ValidateAPIKey enforces the API key charset/length rule (FR10).
func ValidateAPIKey(key string) error {
	if !apiKeyPattern.MatchString(key) {
		return ErrInvalidAPIKey
	}
	return nil
}

// ValidateTier enforces the tier-name charset/length rule.
func ValidateTier(tier string) error {
	if tier == "" {
		return nil // empty means "use default tier"; not an error
	}
	if !tierPattern.MatchString(tier) {
		return ErrInvalidTier
	}
	return nil
}

// SanitizeForLog strips control characters (including CR/LF, which could
// otherwise be used for log injection / forged log lines, threat T7) and
// truncates to a reasonable length before a value is written to a log or
// audit record.
func SanitizeForLog(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\n' || r == '\r' || r < 0x20 {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= 256 {
			break
		}
	}
	out := b.String()
	if len(out) > 256 {
		out = out[:256]
	}
	return out
}

// HashToken computes a salted SHA-256 hex digest of token.
//
// PRODUCTION NOTE: this is a deliberate, clearly-documented substitute for
// bcrypt/argon2 (golang.org/x/crypto was unavailable in the build
// environment — no network access to `go get` it). SHA-256, even salted,
// is fast to brute-force compared to a proper password-hashing function.
// This is acceptable here only because admin bearer tokens are expected
// to be long, high-entropy, randomly-generated secrets (not human
// passwords) compared in constant time — not because SHA-256 is an
// appropriate general-purpose password hash. Swap in bcrypt or argon2id
// before using human-chosen passwords for anything.
func HashToken(token, salt string) string {
	h := sha256.Sum256([]byte(salt + ":" + token))
	return hex.EncodeToString(h[:])
}

// ConstantTimeEqual compares two strings without leaking timing
// information about *where* they first differ (mitigates timing-based
// credential guessing). Note that, as with crypto/subtle generally, a
// length mismatch is detected immediately rather than in constant time;
// this is standard practice since callers here compare fixed-length
// SHA-256 hex digests, where length never varies with secret content.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ValidateBucketConfig bounds-checks admin-supplied bucket parameters
// before they are applied, so a malformed or malicious admin request
// cannot create a bucket that defeats rate limiting (e.g. MaxTokens of
// 0 or a negative RefillInterval).
func ValidateBucketConfig(maxTokens, refillRate int64, refillInterval time.Duration) error {
	if maxTokens < 1 || maxTokens > 1_000_000 {
		return fmt.Errorf("max_tokens out of range [1, 1000000]: %d", maxTokens)
	}
	if refillRate < 0 || refillRate > 100_000 {
		return fmt.Errorf("refill_rate out of range [0, 100000]: %d", refillRate)
	}
	if refillRate > 0 {
		if refillInterval < 10*time.Millisecond || refillInterval > time.Hour {
			return fmt.Errorf("refill_interval out of range [10ms, 1h]: %v", refillInterval)
		}
	}
	return nil
}
