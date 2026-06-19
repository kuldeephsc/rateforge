// Package store implements BucketStore, the central in-memory structure
// that owns every client's token buckets (FR1, B2), the global bucket
// (B3), the per-IP anti-evasion bucket (B5), and LRU eviction at client
// capacity (FR9).
//
// BucketStore does not import internal/scheduler directly; instead it
// defines a small local Scheduler interface that internal/scheduler's
// *Scheduler satisfies structurally. This breaks what would otherwise be
// an import cycle (scheduler -> store -> scheduler) since the scheduler's
// RefillFunc callback is store.OnDue.
package store

import (
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sentinel/internal/bucket"
	"sentinel/internal/multibucket"
)

// Scheduler is the subset of *scheduler.Scheduler that the store depends
// on. Defined locally to avoid an import cycle.
type Scheduler interface {
	Schedule(id string, next time.Time)
	Remove(id string)
}

const (
	globalBucketID = "__global__"
	ipIDPrefix     = "__ip__|"
)

// encodeID builds the scheduler id for a (clientKey, tier) pair.
func encodeID(clientKey, tier string) string { return clientKey + "|" + tier }

// decodeID is the inverse of encodeID. Safe because clientKey and tier are
// both validated against charset regexes (internal/security) that exclude
// '|', so the first '|' unambiguously separates them.
func decodeID(id string) (clientKey, tier string, ok bool) {
	key, tier, found := strings.Cut(id, "|")
	if !found {
		return "", "", false
	}
	return key, tier, true
}

// AllowRequest describes one inbound decision request.
type AllowRequest struct {
	ClientKey string
	SourceIP  string
	Tier      string
	Now       time.Time
}

// AllowResult is the outcome of a decision.
type AllowResult struct {
	Allowed         bool
	RemainingTokens int64
	RetryAfter      time.Duration
	Reason          string // "ok", "blocked", "client_limit", "ip_limit", "global_limit"
}

// TierStatus is the admin-facing view of one tier's bucket state.
type TierStatus struct {
	TokensRemaining  int64 `json:"tokens_remaining"`
	MaxTokens        int64 `json:"max_tokens"`
	RefillRate       int64 `json:"refill_rate"`
	RefillIntervalMs int64 `json:"refill_interval_ms"`
}

// ClientStatus is the admin-facing view of one client's full state.
type ClientStatus struct {
	ClientKey string                `json:"client_key"`
	Blocked   bool                  `json:"blocked"`
	Tiers     map[string]TierStatus `json:"tiers"`
}

// Options configures a new BucketStore. Note that the scheduler is
// deliberately not part of Options — it is wired in afterwards via
// AttachScheduler, because the scheduler itself needs store.OnDue as its
// callback (a chicken-and-egg dependency that AttachScheduler breaks).
type Options struct {
	MaxClients   int
	TierDefaults map[string]bucket.Config
	Logger       *slog.Logger
}

// BucketStore is the central registry of all rate-limiting state.
type BucketStore struct {
	mu           sync.RWMutex
	clients      map[string]*multibucket.ClientBuckets
	maxClients   int
	tierDefaults map[string]bucket.Config
	logger       *slog.Logger

	// scheduler is set exactly once during startup via AttachScheduler,
	// before the store is exposed to concurrent traffic. It is not safe
	// to call AttachScheduler concurrently with Allow/OnDue.
	scheduler Scheduler

	globalBucket atomic.Pointer[bucket.Bucket]
	evictions    atomic.Int64

	ipMu           sync.RWMutex
	ipBuckets      map[string]*bucket.Bucket
	ipBucketCap    int
	ipLimitEnabled atomic.Bool
	ipConfigPtr    atomic.Pointer[bucket.Config]
}

// New creates a BucketStore. If opts.TierDefaults has no "default" entry,
// a conservative built-in default is installed so that getOrCreateClient
// always has something usable to configure new clients with.
func New(opts Options) *BucketStore {
	td := make(map[string]bucket.Config, len(opts.TierDefaults)+1)
	for k, v := range opts.TierDefaults {
		td[k] = v
	}
	if _, ok := td[multibucket.DefaultTier]; !ok {
		td[multibucket.DefaultTier] = bucket.Config{
			MaxTokens:        100,
			RefillRate:       10,
			RefillInterval:   time.Second,
			TokensPerRequest: 1,
		}
	}

	ipCap := opts.MaxClients * 4
	if ipCap <= 0 {
		ipCap = 200000
	}

	return &BucketStore{
		clients:      make(map[string]*multibucket.ClientBuckets),
		maxClients:   opts.MaxClients,
		tierDefaults: td,
		logger:       opts.Logger,
		ipBuckets:    make(map[string]*bucket.Bucket),
		ipBucketCap:  ipCap,
	}
}

// AttachScheduler wires a scheduler into the store after construction. See
// the scheduler field's doc comment for the startup-ordering requirement.
func (s *BucketStore) AttachScheduler(sched Scheduler) {
	s.scheduler = sched
}

// Allow is the hot-path decision function (FR2/FR3). Checks, in order:
// global bucket -> per-IP secondary bucket -> per-client tiered bucket.
// Each gate is cheaper than the next and fails fast.
func (s *BucketStore) Allow(req AllowRequest) AllowResult {
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}

	if gb := s.globalBucket.Load(); gb != nil {
		if allowed, retryAfter := gb.Allow(now); !allowed {
			return AllowResult{Allowed: false, RetryAfter: retryAfter, Reason: "global_limit"}
		}
	}

	if s.ipLimitEnabled.Load() && req.SourceIP != "" {
		ipBucket := s.getOrCreateIPBucket(req.SourceIP, now)
		if allowed, retryAfter := ipBucket.Allow(now); !allowed {
			return AllowResult{Allowed: false, RetryAfter: retryAfter, Reason: "ip_limit"}
		}
	}

	cb, _ := s.getOrCreateClient(req.ClientKey, now)
	if cb.IsBlocked() {
		return AllowResult{Allowed: false, Reason: "blocked", RetryAfter: time.Second}
	}

	s.ensureTier(cb, req.Tier, now)

	allowed, retryAfter := cb.Allow(req.Tier, now)
	if !allowed {
		return AllowResult{Allowed: false, RetryAfter: retryAfter, Reason: "client_limit"}
	}

	var remaining int64
	if b, ok := cb.Bucket(req.Tier); ok {
		remaining = b.TokensRemaining()
	} else if b, ok := cb.Bucket(multibucket.DefaultTier); ok {
		remaining = b.TokensRemaining()
	}

	return AllowResult{Allowed: true, RemainingTokens: remaining, Reason: "ok"}
}

// getOrCreateClient returns the ClientBuckets for key, creating it (with a
// freshly configured default tier) if it does not exist. The bool return
// is true if the client was newly created.
func (s *BucketStore) getOrCreateClient(key string, now time.Time) (*multibucket.ClientBuckets, bool) {
	s.mu.RLock()
	cb, ok := s.clients[key]
	s.mu.RUnlock()
	if ok {
		return cb, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if cb, ok = s.clients[key]; ok {
		return cb, false
	}

	if s.maxClients > 0 && len(s.clients) >= s.maxClients {
		s.evictLRULocked()
	}

	cb = multibucket.New(key)
	defaultCfg := s.tierDefaults[multibucket.DefaultTier]
	cb.Configure(multibucket.DefaultTier, defaultCfg, now)
	s.clients[key] = cb

	if s.scheduler != nil && defaultCfg.RefillInterval > 0 {
		if b, ok := cb.Bucket(multibucket.DefaultTier); ok {
			s.scheduler.Schedule(encodeID(key, multibucket.DefaultTier), b.NextRefillTime())
		}
	}

	return cb, true
}

// ensureTier lazily configures a non-default tier's bucket from
// tierDefaults the first time a client uses it (B2). If no defaults exist
// for the requested tier, this is a no-op and ClientBuckets.Allow will
// fall back to the default tier.
func (s *BucketStore) ensureTier(cb *multibucket.ClientBuckets, tier string, now time.Time) {
	if tier == "" || tier == multibucket.DefaultTier {
		return
	}
	if _, ok := cb.Bucket(tier); ok {
		return
	}

	s.mu.RLock()
	cfg, ok := s.tierDefaults[tier]
	s.mu.RUnlock()
	if !ok {
		return
	}

	cb.Configure(tier, cfg, now)
	if s.scheduler != nil && cfg.RefillInterval > 0 {
		if b, ok := cb.Bucket(tier); ok {
			s.scheduler.Schedule(encodeID(cb.Key(), tier), b.NextRefillTime())
		}
	}
}

// evictLRULocked evicts the least-recently-used client. Caller must hold
// s.mu for writing. Scans the map rather than maintaining a linked list,
// since this only runs at capacity (a rare event), keeping the hot Allow
// path lock-cheap (NFR2.1: Allow acquires only a read lock for the common
// case).
func (s *BucketStore) evictLRULocked() {
	if len(s.clients) == 0 {
		return
	}

	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, cb := range s.clients {
		la := cb.LastAccess()
		if first || la.Before(oldestTime) {
			oldestKey, oldestTime, first = k, la, false
		}
	}
	if oldestKey == "" {
		return
	}

	cb := s.clients[oldestKey]
	delete(s.clients, oldestKey)
	s.evictions.Add(1)

	if s.scheduler != nil {
		for _, tier := range cb.Tiers() {
			s.scheduler.Remove(encodeID(oldestKey, tier))
		}
	}
	if s.logger != nil {
		s.logger.Info("evicted client at capacity (LRU)", "client_key", oldestKey)
	}
}

// getOrCreateIPBucket returns the per-IP secondary bucket for ip (B5: a
// rough anti-evasion control that limits total requests per source IP
// regardless of how many distinct API keys are presented from it).
func (s *BucketStore) getOrCreateIPBucket(ip string, now time.Time) *bucket.Bucket {
	s.ipMu.RLock()
	b, ok := s.ipBuckets[ip]
	s.ipMu.RUnlock()
	if ok {
		return b
	}

	s.ipMu.Lock()
	defer s.ipMu.Unlock()

	if b, ok = s.ipBuckets[ip]; ok {
		return b
	}

	cfgPtr := s.ipConfigPtr.Load()
	var cfg bucket.Config
	if cfgPtr != nil {
		cfg = *cfgPtr
	} else {
		// Defensive fallback; SetIPLimit should always set this together
		// with enabling the flag, but fail open-ish with a generous
		// default rather than panicking if it somehow wasn't.
		cfg = bucket.Config{MaxTokens: 1000, RefillRate: 1000, RefillInterval: time.Second}
	}

	if len(s.ipBuckets) >= s.ipBucketCap {
		s.evictOldestIPLocked()
	}

	b = bucket.New(cfg, now)
	s.ipBuckets[ip] = b

	if s.scheduler != nil && cfg.RefillInterval > 0 {
		s.scheduler.Schedule(ipIDPrefix+ip, b.NextRefillTime())
	}

	return b
}

// evictOldestIPLocked evicts the least-recently-used per-IP bucket. Caller
// must hold s.ipMu for writing.
func (s *BucketStore) evictOldestIPLocked() {
	if len(s.ipBuckets) == 0 {
		return
	}
	var oldestIP string
	var oldestTime time.Time
	first := true
	for ip, b := range s.ipBuckets {
		la := b.LastAccess()
		if first || la.Before(oldestTime) {
			oldestIP, oldestTime, first = ip, la, false
		}
	}
	if oldestIP == "" {
		return
	}
	delete(s.ipBuckets, oldestIP)
	if s.scheduler != nil {
		s.scheduler.Remove(ipIDPrefix + oldestIP)
	}
}

// OnDue is the scheduler's RefillFunc callback (FR4). It dispatches based
// on the id's encoding: the global bucket, a per-IP bucket, or a
// per-client-tier bucket.
func (s *BucketStore) OnDue(id string, now time.Time) (time.Time, bool) {
	if id == globalBucketID {
		gb := s.globalBucket.Load()
		if gb == nil {
			return time.Time{}, false
		}
		gb.ScheduledRefill(now)
		return gb.NextRefillTime(), true
	}

	if strings.HasPrefix(id, ipIDPrefix) {
		ip := strings.TrimPrefix(id, ipIDPrefix)
		s.ipMu.RLock()
		b, ok := s.ipBuckets[ip]
		s.ipMu.RUnlock()
		if !ok {
			return time.Time{}, false
		}
		b.ScheduledRefill(now)
		return b.NextRefillTime(), true
	}

	key, tier, ok := decodeID(id)
	if !ok {
		return time.Time{}, false
	}

	s.mu.RLock()
	cb, ok := s.clients[key]
	s.mu.RUnlock()
	if !ok {
		return time.Time{}, false // client was evicted; drop the schedule
	}

	b, ok := cb.Bucket(tier)
	if !ok {
		return time.Time{}, false
	}
	b.ScheduledRefill(now)
	return b.NextRefillTime(), true
}

// EnsureClient returns the ClientBuckets for key, creating it with default
// settings if it does not already exist. Used by admin handlers that may
// target a client that has not yet made a request (e.g. pre-blocking).
func (s *BucketStore) EnsureClient(key string, now time.Time) *multibucket.ClientBuckets {
	cb, _ := s.getOrCreateClient(key, now)
	return cb
}

// UpdateClientConfig sets (or replaces) the configuration for one tier of
// one client, creating the client if necessary (admin hot reload, FR8).
func (s *BucketStore) UpdateClientConfig(key, tier string, cfg bucket.Config, now time.Time) {
	if tier == "" {
		tier = multibucket.DefaultTier
	}
	cb := s.EnsureClient(key, now)
	cb.Configure(tier, cfg, now)

	if s.scheduler != nil {
		id := encodeID(key, tier)
		s.scheduler.Remove(id)
		if cfg.RefillInterval > 0 {
			if b, ok := cb.Bucket(tier); ok {
				s.scheduler.Schedule(id, b.NextRefillTime())
			}
		}
	}
}

// TierConfig returns the effective configuration for (key, tier): the
// client's existing bucket config if already configured, else the
// configured defaults for that tier, else the "default" tier's defaults.
// Used by the admin API to implement merge-patch semantics on partial
// config updates.
func (s *BucketStore) TierConfig(key, tier string) bucket.Config {
	if tier == "" {
		tier = multibucket.DefaultTier
	}

	s.mu.RLock()
	cb, ok := s.clients[key]
	s.mu.RUnlock()
	if ok {
		if b, ok := cb.Bucket(tier); ok {
			return b.Config()
		}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if cfg, ok := s.tierDefaults[tier]; ok {
		return cfg
	}
	return s.tierDefaults[multibucket.DefaultTier]
}

// Block administratively blocks a client (creating it if necessary).
func (s *BucketStore) Block(key string, now time.Time) {
	cb := s.EnsureClient(key, now)
	cb.BlockAll()
}

// Unblock clears an administrative block. No-op if the client is unknown.
func (s *BucketStore) Unblock(key string) {
	s.mu.RLock()
	cb, ok := s.clients[key]
	s.mu.RUnlock()
	if !ok {
		return
	}
	cb.UnblockAll()
}

// Status returns the current state of one client, or false if unknown.
func (s *BucketStore) Status(key string) (ClientStatus, bool) {
	s.mu.RLock()
	cb, ok := s.clients[key]
	s.mu.RUnlock()
	if !ok {
		return ClientStatus{}, false
	}
	return s.buildStatus(key, cb), true
}

// ListClients returns the current state of every known client.
func (s *BucketStore) ListClients() []ClientStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ClientStatus, 0, len(s.clients))
	for k, cb := range s.clients {
		out = append(out, s.buildStatus(k, cb))
	}
	return out
}

func (s *BucketStore) buildStatus(key string, cb *multibucket.ClientBuckets) ClientStatus {
	tiers := make(map[string]TierStatus)
	for _, t := range cb.Tiers() {
		if b, ok := cb.Bucket(t); ok {
			cfg := b.Config()
			tiers[t] = TierStatus{
				TokensRemaining:  b.TokensRemaining(),
				MaxTokens:        cfg.MaxTokens,
				RefillRate:       cfg.RefillRate,
				RefillIntervalMs: cfg.RefillInterval.Milliseconds(),
			}
		}
	}
	return ClientStatus{ClientKey: key, Blocked: cb.IsBlocked(), Tiers: tiers}
}

// ActiveClients returns the current number of tracked clients, for
// metrics.
func (s *BucketStore) ActiveClients() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients)
}

// Evictions returns the cumulative number of LRU client evictions, for
// metrics.
func (s *BucketStore) Evictions() int64 {
	return s.evictions.Load()
}

// SetGlobalConfig enables (or reconfigures) the global rate limit bucket
// (B3), which gates every request regardless of client.
func (s *BucketStore) SetGlobalConfig(cfg bucket.Config, now time.Time) {
	gb := bucket.New(cfg, now)
	s.globalBucket.Store(gb)

	if s.scheduler != nil {
		s.scheduler.Remove(globalBucketID)
		if cfg.RefillInterval > 0 {
			s.scheduler.Schedule(globalBucketID, gb.NextRefillTime())
		}
	}
}

// DisableGlobal removes the global bucket entirely, so requests are no
// longer gated by it.
func (s *BucketStore) DisableGlobal() {
	s.globalBucket.Store(nil)
	if s.scheduler != nil {
		s.scheduler.Remove(globalBucketID)
	}
}

// SetIPLimit enables or disables the per-IP secondary anti-evasion limit
// (B5). Disabling clears all existing per-IP bucket state.
func (s *BucketStore) SetIPLimit(enabled bool, cfg bucket.Config) {
	s.ipLimitEnabled.Store(enabled)
	normalized := cfg
	s.ipConfigPtr.Store(&normalized)

	if enabled {
		return
	}

	s.ipMu.Lock()
	defer s.ipMu.Unlock()
	for ip := range s.ipBuckets {
		if s.scheduler != nil {
			s.scheduler.Remove(ipIDPrefix + ip)
		}
		delete(s.ipBuckets, ip)
	}
}
