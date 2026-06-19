package bucket

import (
	"sync"
	"testing"
	"time"
)

func cfg(max, rate int64, interval time.Duration) Config {
	return Config{MaxTokens: max, RefillRate: rate, RefillInterval: interval, TokensPerRequest: 1}
}

func TestAllowWithinCapacity(t *testing.T) {
	now := time.Now()
	b := New(cfg(5, 1, time.Second), now)

	for i := 0; i < 5; i++ {
		allowed, _ := b.Allow(now)
		if !allowed {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	allowed, retry := b.Allow(now)
	if allowed {
		t.Fatal("6th request should be rejected")
	}
	if retry <= 0 {
		t.Fatal("expected positive retry-after on rejection")
	}
}

func TestLazyRefillOverTime(t *testing.T) {
	now := time.Now()
	b := New(cfg(2, 1, time.Second), now)

	b.Allow(now)
	b.Allow(now)
	if allowed, _ := b.Allow(now); allowed {
		t.Fatal("expected rejection at zero tokens")
	}

	later := now.Add(3 * time.Second) // +3 intervals, clamped to MaxTokens=2
	if allowed, _ := b.Allow(later); !allowed {
		t.Fatal("expected allowance after refill")
	}
	if remaining := b.TokensRemaining(); remaining != 1 {
		t.Fatalf("expected 1 token remaining after refill+consume, got %d", remaining)
	}
}

func TestBlockedBucketRejectsImmediately(t *testing.T) {
	now := time.Now()
	b := New(cfg(10, 1, time.Second), now)
	b.Block()
	if allowed, retry := b.Allow(now); allowed || retry != 0 {
		t.Fatal("blocked bucket must reject with zero retry-after")
	}
	b.Unblock()
	if allowed, _ := b.Allow(now); !allowed {
		t.Fatal("unblocked bucket should allow again")
	}
}

func TestUpdateConfigClampsTokens(t *testing.T) {
	now := time.Now()
	b := New(cfg(100, 10, time.Second), now)
	if b.TokensRemaining() != 100 {
		t.Fatalf("expected 100 tokens initially, got %d", b.TokensRemaining())
	}
	b.UpdateConfig(cfg(10, 10, time.Second))
	if b.TokensRemaining() != 10 {
		t.Fatalf("expected tokens clamped to new max 10, got %d", b.TokensRemaining())
	}
}

func TestConcurrentAllowNeverOverdraws(t *testing.T) {
	now := time.Now()
	b := New(cfg(1000, 0, 0), now) // no refill: easiest to assert exact totals

	var wg sync.WaitGroup
	var allowedCount int64
	var mu sync.Mutex

	workers := 50
	perWorker := 100
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			local := 0
			for j := 0; j < perWorker; j++ {
				if allowed, _ := b.Allow(now); allowed {
					local++
				}
			}
			mu.Lock()
			allowedCount += int64(local)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if allowedCount != 1000 {
		t.Fatalf("expected exactly 1000 allowed requests (no over/under-draw), got %d", allowedCount)
	}
	if remaining := b.TokensRemaining(); remaining != 0 {
		t.Fatalf("expected 0 tokens remaining, got %d", remaining)
	}
}

func TestPanicRecoveryFailsClosed(t *testing.T) {
	now := time.Now()
	b := New(cfg(10, 1, time.Second), now)
	// Force a nil-config panic path by clearing the pointer.
	b.configPtr.Store(nil)
	allowed, _ := b.Allow(now)
	if allowed {
		t.Fatal("expected fail-closed rejection on internal panic")
	}
}
