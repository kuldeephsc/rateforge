package window

import (
	"testing"
	"time"
)

func TestSlidingWindowAllowsUpToLimit(t *testing.T) {
	w := New(Config{WindowDuration: time.Second, MaxRequests: 3, BufferSize: 10})
	now := time.Now()

	for i := 0; i < 3; i++ {
		if !w.Allow(now) {
			t.Fatalf("expected request %d to be allowed", i)
		}
	}
	if w.Allow(now) {
		t.Fatal("expected 4th request within window to be rejected")
	}
}

func TestSlidingWindowExpiresOldEntries(t *testing.T) {
	w := New(Config{WindowDuration: 100 * time.Millisecond, MaxRequests: 2, BufferSize: 10})
	now := time.Now()

	if !w.Allow(now) || !w.Allow(now) {
		t.Fatal("expected first two requests to be allowed")
	}
	if w.Allow(now) {
		t.Fatal("expected third immediate request to be rejected")
	}

	later := now.Add(200 * time.Millisecond)
	if !w.Allow(later) {
		t.Fatal("expected request after window expiry to be allowed")
	}
}

func TestSlidingWindowAutoCorrectsBufferSize(t *testing.T) {
	// BufferSize is intentionally smaller than MaxRequests; it must be
	// auto-corrected to MaxRequests+1 to avoid silent under-enforcement.
	w := New(Config{WindowDuration: time.Second, MaxRequests: 50, BufferSize: 1})
	if len(w.timestamps) < 51 {
		t.Fatalf("expected buffer size >= 51, got %d", len(w.timestamps))
	}

	now := time.Now()
	allowed := 0
	for i := 0; i < 60; i++ {
		if w.Allow(now) {
			allowed++
		}
	}
	if allowed != 50 {
		t.Fatalf("expected exactly 50 allowed requests, got %d", allowed)
	}
}

func TestSlidingWindowCleanup(t *testing.T) {
	w := New(Config{WindowDuration: 50 * time.Millisecond, MaxRequests: 5, BufferSize: 10})
	now := time.Now()
	w.Allow(now)
	w.Allow(now)
	if w.Count() != 2 {
		t.Fatalf("expected count 2, got %d", w.Count())
	}
	w.Cleanup(now.Add(100 * time.Millisecond))
	if w.Count() != 0 {
		t.Fatalf("expected count 0 after cleanup, got %d", w.Count())
	}
}
