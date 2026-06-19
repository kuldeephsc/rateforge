package security

import (
	"testing"
	"time"
)

func TestValidateAPIKey(t *testing.T) {
	valid := []string{"abc123", "client-key_1", "A", "a-b-c_D-1"}
	for _, v := range valid {
		if err := ValidateAPIKey(v); err != nil {
			t.Errorf("expected %q to be valid, got error: %v", v, err)
		}
	}

	invalid := []string{"", "has space", "has/slash", "has|pipe", "semi;colon", string(make([]byte, 200))}
	for _, v := range invalid {
		if err := ValidateAPIKey(v); err == nil {
			t.Errorf("expected %q to be invalid", v)
		}
	}
}

func TestValidateTierAllowsEmpty(t *testing.T) {
	if err := ValidateTier(""); err != nil {
		t.Fatalf("expected empty tier (= default) to be valid, got: %v", err)
	}
	if err := ValidateTier("read-heavy_1"); err != nil {
		t.Fatalf("expected valid tier name to pass, got: %v", err)
	}
	if err := ValidateTier("bad tier"); err == nil {
		t.Fatalf("expected tier with space to be rejected")
	}
}

func TestSanitizeForLogStripsControlChars(t *testing.T) {
	in := "hello\r\nworld\x00\x01end"
	out := SanitizeForLog(in)
	if out != "helloworldend" {
		t.Fatalf("expected control chars stripped, got %q", out)
	}
}

func TestSanitizeForLogTruncates(t *testing.T) {
	long := make([]byte, 1000)
	for i := range long {
		long[i] = 'a'
	}
	out := SanitizeForLog(string(long))
	if len(out) > 256 {
		t.Fatalf("expected output truncated to <=256 chars, got %d", len(out))
	}
}

func TestHashTokenIsDeterministicAndSaltSensitive(t *testing.T) {
	h1 := HashToken("secret", "salt-a")
	h2 := HashToken("secret", "salt-a")
	h3 := HashToken("secret", "salt-b")

	if h1 != h2 {
		t.Fatalf("expected deterministic hash for same token+salt")
	}
	if h1 == h3 {
		t.Fatalf("expected different hash for different salt")
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !ConstantTimeEqual("abc", "abc") {
		t.Fatalf("expected equal strings to compare equal")
	}
	if ConstantTimeEqual("abc", "abd") {
		t.Fatalf("expected different strings to compare unequal")
	}
	if ConstantTimeEqual("abc", "abcd") {
		t.Fatalf("expected different-length strings to compare unequal")
	}
}

func TestValidateBucketConfigBounds(t *testing.T) {
	if err := ValidateBucketConfig(100, 10, time.Second); err != nil {
		t.Fatalf("expected valid config to pass, got: %v", err)
	}
	if err := ValidateBucketConfig(0, 10, time.Second); err == nil {
		t.Fatalf("expected max_tokens=0 to be rejected")
	}
	if err := ValidateBucketConfig(100, 10, time.Millisecond); err == nil {
		t.Fatalf("expected refill_interval below 10ms (with positive rate) to be rejected")
	}
	if err := ValidateBucketConfig(100, -1, time.Second); err == nil {
		t.Fatalf("expected negative refill_rate to be rejected")
	}
	if err := ValidateBucketConfig(100, 0, 0); err != nil {
		t.Fatalf("expected refill_rate=0 (no refill) with any interval to be valid, got: %v", err)
	}
}
