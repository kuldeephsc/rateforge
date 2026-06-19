// Package multibucket implements per-client multi-tier rate limiting (FR1 + B2).
//
// Every client in Sentinel is represented as a ClientBuckets value, which is
// a small map of tier-name -> *bucket.Bucket. Clients that never use the
// X-Resource-Tier header simply have a single bucket under DefaultTier, so
// the "simple" FR1 case and the "bonus" B2 case share one code path.
package multibucket

import (
	"sync"
	"time"

	"sentinel/internal/bucket"
)

// DefaultTier is the tier used when a client does not specify
// X-Resource-Tier, or when no tiers have been configured.
const DefaultTier = "default"

// ClientBuckets holds all per-tier token buckets for a single client.
type ClientBuckets struct {
	clientKey string

	mu      sync.RWMutex
	buckets map[string]*bucket.Bucket
}

// New creates an empty ClientBuckets for the given client key. Buckets are
// added lazily via Configure as tiers are first used.
func New(clientKey string) *ClientBuckets {
	return &ClientBuckets{
		clientKey: clientKey,
		buckets:   make(map[string]*bucket.Bucket),
	}
}

// Key returns the client key this ClientBuckets belongs to.
func (cb *ClientBuckets) Key() string {
	return cb.clientKey
}

// Configure creates or replaces the bucket for the given tier.
func (cb *ClientBuckets) Configure(tier string, cfg bucket.Config, now time.Time) *bucket.Bucket {
	if tier == "" {
		tier = DefaultTier
	}
	b := bucket.New(cfg, now)
	cb.mu.Lock()
	cb.buckets[tier] = b
	cb.mu.Unlock()
	return b
}

// Bucket returns the bucket for a tier (or nil, false if not configured).
func (cb *ClientBuckets) Bucket(tier string) (*bucket.Bucket, bool) {
	if tier == "" {
		tier = DefaultTier
	}
	cb.mu.RLock()
	b, ok := cb.buckets[tier]
	cb.mu.RUnlock()
	return b, ok
}

// Allow attempts to consume one unit from the bucket for the given tier. If
// the tier has not been configured, it falls back to DefaultTier. If no
// buckets exist at all (mis-wired client), it fails closed (denies).
func (cb *ClientBuckets) Allow(tier string, now time.Time) (bool, time.Duration) {
	if tier == "" {
		tier = DefaultTier
	}

	cb.mu.RLock()
	b, ok := cb.buckets[tier]
	if !ok {
		b, ok = cb.buckets[DefaultTier]
	}
	cb.mu.RUnlock()

	if !ok || b == nil {
		// Fail closed: a client with no configured buckets at all should
		// not be allowed through.
		return false, time.Second
	}
	return b.Allow(now)
}

// Tiers returns the list of currently configured tier names.
func (cb *ClientBuckets) Tiers() []string {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	tiers := make([]string, 0, len(cb.buckets))
	for t := range cb.buckets {
		tiers = append(tiers, t)
	}
	return tiers
}

// BlockAll marks every tier's bucket as administratively blocked.
func (cb *ClientBuckets) BlockAll() {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	for _, b := range cb.buckets {
		b.Block()
	}
}

// UnblockAll clears the administrative block on every tier's bucket.
func (cb *ClientBuckets) UnblockAll() {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	for _, b := range cb.buckets {
		b.Unblock()
	}
}

// IsBlocked reports whether any tier is blocked (tiers are blocked/unblocked
// together via BlockAll/UnblockAll, so checking any one is representative,
// but we check all defensively in case of future per-tier blocking).
func (cb *ClientBuckets) IsBlocked() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	for _, b := range cb.buckets {
		if b.IsBlocked() {
			return true
		}
	}
	return false
}

// LastAccess returns the most recent access time across all tiers. Used by
// the store for LRU eviction so a client that is hot on any tier is not
// evicted.
func (cb *ClientBuckets) LastAccess() time.Time {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	var latest time.Time
	for _, b := range cb.buckets {
		if t := b.LastAccess(); t.After(latest) {
			latest = t
		}
	}
	return latest
}
