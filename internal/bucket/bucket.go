// Package bucket implements a single client's token bucket: a hybrid
// rate limiter that combines lazy (on-access) refill for correctness with
// support for scheduler-driven proactive refill for efficiency (see
// internal/scheduler). The hot path (Allow) is entirely lock-free, relying
// on atomics and CAS loops instead of a mutex.
package bucket

import (
	"sync/atomic"
	"time"

	"sentinel/internal/window"
)

// Config holds a bucket's tunable parameters. It is treated as immutable
// once published via atomic.Pointer — admin updates create and swap in a
// new Config rather than mutating fields in place.
type Config struct {
	MaxTokens        int64
	RefillRate       int64 // tokens added per RefillInterval
	RefillInterval   time.Duration
	TokensPerRequest int64          // tokens consumed per request; default 1
	SlidingWindow    *window.Config // optional stricter secondary constraint
}

// Bucket is a single client's (or tier's, or the global) token bucket.
// Every field that can be touched on the request hot path is atomic, so
// the struct intentionally carries no sync.Mutex.
type Bucket struct {
	configPtr      atomic.Pointer[Config]
	tokens         atomic.Int64
	lastRefillTime atomic.Int64 // unix nanos
	blocked        atomic.Bool
	lastAccessTime atomic.Int64 // unix nanos, used for LRU eviction
	createdAt      time.Time
	windowPtr      atomic.Pointer[window.SlidingWindow]
}

// New creates a fully-initialized Bucket starting at full capacity.
func New(cfg Config, now time.Time) *Bucket {
	b := &Bucket{createdAt: now}
	normalized := normalize(cfg)
	b.configPtr.Store(&normalized)
	b.tokens.Store(normalized.MaxTokens)
	b.lastRefillTime.Store(now.UnixNano())
	b.lastAccessTime.Store(now.UnixNano())
	if normalized.SlidingWindow != nil && normalized.SlidingWindow.Enabled {
		b.windowPtr.Store(window.New(*normalized.SlidingWindow))
	}
	return b
}

func normalize(cfg Config) Config {
	if cfg.TokensPerRequest <= 0 {
		cfg.TokensPerRequest = 1
	}
	return cfg
}

// Allow attempts to consume TokensPerRequest tokens at time `now`. It is
// safe for concurrent use by many goroutines without external locking.
//
// On rejection, retryAfter is a best-effort estimate of how long the
// caller should wait before the bucket is expected to have enough tokens.
//
// Fail-closed: any panic during evaluation results in a rejection rather
// than propagating, per design decision D7.
func (b *Bucket) Allow(now time.Time) (allowed bool, retryAfter time.Duration) {
	defer func() {
		if r := recover(); r != nil {
			allowed = false
			retryAfter = time.Second
		}
	}()

	if b.blocked.Load() {
		return false, 0
	}

	cfg := b.configPtr.Load()
	n := cfg.TokensPerRequest
	if n <= 0 {
		n = 1
	}

	if cfg.RefillInterval > 0 {
		b.lazyRefill(now, cfg)
	}
	b.lastAccessTime.Store(now.UnixNano())

	for {
		current := b.tokens.Load()
		if current < n {
			if cfg.RefillRate <= 0 || cfg.RefillInterval <= 0 {
				return false, time.Second
			}
			deficit := n - current
			intervals := (deficit + cfg.RefillRate - 1) / cfg.RefillRate
			return false, time.Duration(intervals) * cfg.RefillInterval
		}
		if b.tokens.CompareAndSwap(current, current-n) {
			// Token bucket allows the request; now check the optional
			// sliding window. If the window rejects, refund the tokens
			// so the bucket's state is unaffected by the rejected request.
			if w := b.windowPtr.Load(); w != nil && !w.Allow(now) {
				b.tokens.Add(n)
				return false, cfg.RefillInterval
			}
			return true, 0
		}
		// CAS lost the race against a concurrent Allow/refill; retry.
	}
}

// lazyRefill applies any refill intervals that have elapsed since the last
// refill. A CAS on lastRefillTime ensures that concurrent callers cannot
// double-apply the same interval (design decision D11).
func (b *Bucket) lazyRefill(now time.Time, cfg *Config) {
	for {
		lastNano := b.lastRefillTime.Load()
		last := time.Unix(0, lastNano)
		elapsed := now.Sub(last)
		intervals := int64(elapsed / cfg.RefillInterval)
		if intervals <= 0 {
			return
		}

		newLastNano := last.Add(time.Duration(intervals) * cfg.RefillInterval).UnixNano()
		if !b.lastRefillTime.CompareAndSwap(lastNano, newLastNano) {
			continue // another goroutine refilled concurrently; retry
		}

		tokensToAdd := intervals * cfg.RefillRate
		for {
			current := b.tokens.Load()
			updated := current + tokensToAdd
			if updated > cfg.MaxTokens {
				updated = cfg.MaxTokens
			}
			if b.tokens.CompareAndSwap(current, updated) {
				break
			}
		}
		return
	}
}

// ScheduledRefill is invoked by the RefillScheduler for buckets that are
// due. It performs the same lazy-refill logic; the scheduler is purely an
// efficiency optimization (event-driven, no polling) — lazy refill on the
// request hot path remains the correctness guarantee even if the
// scheduler is delayed or absent.
func (b *Bucket) ScheduledRefill(now time.Time) {
	cfg := b.configPtr.Load()
	if cfg.RefillInterval <= 0 {
		return
	}
	b.lazyRefill(now, cfg)
}

// UpdateConfig atomically swaps in a new configuration. Existing token
// balance is preserved (and clamped to the new MaxTokens); the sliding
// window is rebuilt if its configuration changed.
func (b *Bucket) UpdateConfig(cfg Config) {
	normalized := normalize(cfg)
	b.configPtr.Store(&normalized)

	if current := b.tokens.Load(); current > normalized.MaxTokens {
		b.tokens.Store(normalized.MaxTokens)
	}

	if normalized.SlidingWindow != nil && normalized.SlidingWindow.Enabled {
		b.windowPtr.Store(window.New(*normalized.SlidingWindow))
	} else {
		b.windowPtr.Store(nil)
	}
}

// Block immediately causes all subsequent Allow calls to be rejected,
// regardless of token balance.
func (b *Bucket) Block() { b.blocked.Store(true) }

// Unblock reverses Block.
func (b *Bucket) Unblock() { b.blocked.Store(false) }

// IsBlocked reports the current admin block state.
func (b *Bucket) IsBlocked() bool { return b.blocked.Load() }

// Config returns a copy of the bucket's current configuration.
func (b *Bucket) Config() Config { return *b.configPtr.Load() }

// TokensRemaining returns the current token balance without consuming any.
func (b *Bucket) TokensRemaining() int64 { return b.tokens.Load() }

// LastAccess returns the timestamp of the most recent Allow call, used by
// the store for LRU eviction.
func (b *Bucket) LastAccess() time.Time { return time.Unix(0, b.lastAccessTime.Load()) }

// CreatedAt returns the bucket's creation time.
func (b *Bucket) CreatedAt() time.Time { return b.createdAt }

// NextRefillTime returns the time at which this bucket's next scheduled
// refill is due, or the zero Time if the bucket has no active refill
// interval (e.g. RefillInterval <= 0).
func (b *Bucket) NextRefillTime() time.Time {
	cfg := b.configPtr.Load()
	if cfg.RefillInterval <= 0 {
		return time.Time{}
	}
	last := time.Unix(0, b.lastRefillTime.Load())
	return last.Add(cfg.RefillInterval)
}
