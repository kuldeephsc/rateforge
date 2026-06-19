// Package window implements a sliding-window request counter backed by a
// circular buffer of nanosecond timestamps. It is used as an optional,
// stricter secondary constraint layered on top of a token bucket (see
// internal/bucket), preventing bursty consumption within a sub-interval
// even when the bucket itself still has tokens available.
package window

import (
	"sync"
	"time"
)

// Config describes a sliding window constraint.
type Config struct {
	Enabled        bool
	WindowDuration time.Duration
	MaxRequests    int64
	// BufferSize is the requested ring-buffer capacity. It is auto-corrected
	// upward to MaxRequests+1 to guarantee the window can never silently
	// under-enforce its limit (see design decision D12).
	BufferSize int
}

// SlidingWindow counts requests within a trailing time window using a fixed
// size ring buffer of timestamps, avoiding unbounded memory growth.
type SlidingWindow struct {
	mu          sync.Mutex
	windowSize  time.Duration
	maxRequests int64
	timestamps  []int64
	head        int
	count       int
}

// New constructs a SlidingWindow from cfg. The buffer is sized to at least
// MaxRequests+1 regardless of the configured BufferSize.
func New(cfg Config) *SlidingWindow {
	minSize := int(cfg.MaxRequests) + 1
	bufSize := cfg.BufferSize
	if bufSize < minSize {
		bufSize = minSize
	}
	if bufSize < 1 {
		bufSize = 1
	}
	return &SlidingWindow{
		windowSize:  cfg.WindowDuration,
		maxRequests: cfg.MaxRequests,
		timestamps:  make([]int64, bufSize),
	}
}

// Allow reports whether a request arriving at `now` is permitted under the
// window constraint. On success the timestamp is recorded.
func (w *SlidingWindow) Allow(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	nowNano := now.UnixNano()
	w.compactLocked(nowNano - w.windowSize.Nanoseconds())

	if int64(w.count) >= w.maxRequests {
		return false
	}
	w.pushLocked(nowNano)
	return true
}

// Cleanup proactively evicts expired timestamps without recording a new
// request. Intended to be invoked periodically (e.g. by the scheduler) so
// idle windows don't carry stale state indefinitely.
func (w *SlidingWindow) Cleanup(now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.compactLocked(now.UnixNano() - w.windowSize.Nanoseconds())
}

// Count returns the number of requests currently counted within the window.
func (w *SlidingWindow) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.count
}

func (w *SlidingWindow) compactLocked(cutoff int64) {
	n := len(w.timestamps)
	if n == 0 || w.count == 0 {
		return
	}
	start := (w.head - w.count + n) % n
	for w.count > 0 && w.timestamps[start] <= cutoff {
		start = (start + 1) % n
		w.count--
	}
}

func (w *SlidingWindow) pushLocked(ts int64) {
	n := len(w.timestamps)
	w.timestamps[w.head] = ts
	w.head = (w.head + 1) % n
	// count is bounded by maxRequests < bufSize (see New), so this branch
	// (buffer genuinely full) should never be hit in practice; it exists
	// only as a defensive guard against misconfiguration.
	if w.count < n {
		w.count++
	}
}
