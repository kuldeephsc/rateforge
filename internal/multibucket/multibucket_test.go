package multibucket

import (
	"testing"
	"time"

	"sentinel/internal/bucket"
)

func TestAllowFallsBackToDefaultTier(t *testing.T) {
	now := time.Now()
	cb := New("client-1")
	cb.Configure(DefaultTier, bucket.Config{MaxTokens: 2, RefillRate: 0, RefillInterval: 0}, now)

	// "expensive" tier was never configured; should fall back to default.
	allowed, _ := cb.Allow("expensive", now)
	if !allowed {
		t.Fatalf("expected fallback to default tier to allow")
	}
}

func TestAllowPerTierIndependent(t *testing.T) {
	now := time.Now()
	cb := New("client-1")
	cb.Configure("read", bucket.Config{MaxTokens: 1, RefillRate: 0, RefillInterval: 0}, now)
	cb.Configure("write", bucket.Config{MaxTokens: 1, RefillRate: 0, RefillInterval: 0}, now)

	if allowed, _ := cb.Allow("read", now); !allowed {
		t.Fatalf("expected first read to be allowed")
	}
	if allowed, _ := cb.Allow("read", now); allowed {
		t.Fatalf("expected second read to be denied (exhausted)")
	}
	// Write tier should be unaffected by read tier exhaustion.
	if allowed, _ := cb.Allow("write", now); !allowed {
		t.Fatalf("expected write tier to be independently allowed")
	}
}

func TestAllowFailsClosedWithNoBuckets(t *testing.T) {
	now := time.Now()
	cb := New("client-1") // no tiers configured at all
	allowed, _ := cb.Allow(DefaultTier, now)
	if allowed {
		t.Fatalf("expected fail-closed (deny) when no buckets are configured")
	}
}

func TestBlockAllUnblockAll(t *testing.T) {
	now := time.Now()
	cb := New("client-1")
	cb.Configure("read", bucket.Config{MaxTokens: 5, RefillRate: 0, RefillInterval: 0}, now)
	cb.Configure("write", bucket.Config{MaxTokens: 5, RefillRate: 0, RefillInterval: 0}, now)

	cb.BlockAll()
	if !cb.IsBlocked() {
		t.Fatalf("expected IsBlocked true after BlockAll")
	}
	if allowed, _ := cb.Allow("read", now); allowed {
		t.Fatalf("expected blocked client to be denied")
	}

	cb.UnblockAll()
	if cb.IsBlocked() {
		t.Fatalf("expected IsBlocked false after UnblockAll")
	}
	if allowed, _ := cb.Allow("read", now); !allowed {
		t.Fatalf("expected unblocked client to be allowed")
	}
}

func TestLastAccessTracksMostRecentTier(t *testing.T) {
	now := time.Now()
	cb := New("client-1")
	cb.Configure("read", bucket.Config{MaxTokens: 5, RefillRate: 0, RefillInterval: 0}, now)
	cb.Configure("write", bucket.Config{MaxTokens: 5, RefillRate: 0, RefillInterval: 0}, now)

	later := now.Add(time.Minute)
	cb.Allow("write", later)

	if got := cb.LastAccess(); got.Before(later) {
		t.Fatalf("expected LastAccess to reflect most recent tier access, got %v want >= %v", got, later)
	}
}

func TestTiersListsConfigured(t *testing.T) {
	now := time.Now()
	cb := New("client-1")
	cb.Configure("read", bucket.Config{MaxTokens: 5, RefillInterval: 0}, now)
	cb.Configure("write", bucket.Config{MaxTokens: 5, RefillInterval: 0}, now)

	tiers := cb.Tiers()
	if len(tiers) != 2 {
		t.Fatalf("expected 2 tiers, got %d (%v)", len(tiers), tiers)
	}
}
