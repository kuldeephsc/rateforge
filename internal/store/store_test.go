package store

import (
	"sync"
	"testing"
	"time"

	"sentinel/internal/bucket"
)

// fakeScheduler records Schedule/Remove calls without actually firing
// anything, so tests can assert the store wires scheduling correctly
// without depending on internal/scheduler's timing.
type fakeScheduler struct {
	mu        sync.Mutex
	scheduled map[string]time.Time
	removed   []string
}

func newFakeScheduler() *fakeScheduler {
	return &fakeScheduler{scheduled: make(map[string]time.Time)}
}

func (f *fakeScheduler) Schedule(id string, next time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scheduled[id] = next
}

func (f *fakeScheduler) Remove(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.scheduled, id)
	f.removed = append(f.removed, id)
}

func (f *fakeScheduler) has(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.scheduled[id]
	return ok
}

func testDefaults() map[string]bucket.Config {
	return map[string]bucket.Config{
		"default": {MaxTokens: 3, RefillRate: 1, RefillInterval: time.Minute, TokensPerRequest: 1},
	}
}

func TestAllowBasicGrantAndDeny(t *testing.T) {
	now := time.Now()
	s := New(Options{MaxClients: 10, TierDefaults: testDefaults()})

	for i := 0; i < 3; i++ {
		res := s.Allow(AllowRequest{ClientKey: "alice", Now: now})
		if !res.Allowed {
			t.Fatalf("request %d: expected allowed, got denied (reason=%s)", i, res.Reason)
		}
	}

	res := s.Allow(AllowRequest{ClientKey: "alice", Now: now})
	if res.Allowed {
		t.Fatalf("expected 4th request to be denied")
	}
	if res.Reason != "client_limit" {
		t.Fatalf("expected reason client_limit, got %s", res.Reason)
	}
}

func TestLRUEvictionAtCapacity(t *testing.T) {
	now := time.Now()
	s := New(Options{MaxClients: 2, TierDefaults: testDefaults()})

	s.Allow(AllowRequest{ClientKey: "a", Now: now})
	s.Allow(AllowRequest{ClientKey: "b", Now: now.Add(time.Second)})

	if got := s.ActiveClients(); got != 2 {
		t.Fatalf("expected 2 active clients, got %d", got)
	}

	// "a" is now the least-recently-used; adding "c" should evict it.
	s.Allow(AllowRequest{ClientKey: "c", Now: now.Add(2 * time.Second)})

	if got := s.ActiveClients(); got != 2 {
		t.Fatalf("expected 2 active clients after eviction, got %d", got)
	}
	if _, ok := s.Status("a"); ok {
		t.Fatalf("expected client 'a' to have been evicted")
	}
	if _, ok := s.Status("b"); !ok {
		t.Fatalf("expected client 'b' to still be present")
	}
	if got := s.Evictions(); got != 1 {
		t.Fatalf("expected 1 eviction recorded, got %d", got)
	}
}

func TestGlobalBucketGatesAllClients(t *testing.T) {
	now := time.Now()
	s := New(Options{MaxClients: 10, TierDefaults: testDefaults()})
	s.SetGlobalConfig(bucket.Config{MaxTokens: 1, RefillRate: 0, RefillInterval: 0}, now)

	res := s.Allow(AllowRequest{ClientKey: "alice", Now: now})
	if !res.Allowed {
		t.Fatalf("expected first request to pass global gate, got reason=%s", res.Reason)
	}

	res = s.Allow(AllowRequest{ClientKey: "bob", Now: now})
	if res.Allowed {
		t.Fatalf("expected second request (different client) to be denied by exhausted global bucket")
	}
	if res.Reason != "global_limit" {
		t.Fatalf("expected reason global_limit, got %s", res.Reason)
	}
}

func TestIPSecondaryLimitAppliesAcrossKeys(t *testing.T) {
	now := time.Now()
	s := New(Options{MaxClients: 10, TierDefaults: testDefaults()})
	s.SetIPLimit(true, bucket.Config{MaxTokens: 1, RefillRate: 0, RefillInterval: 0})

	res := s.Allow(AllowRequest{ClientKey: "key1", SourceIP: "1.2.3.4", Now: now})
	if !res.Allowed {
		t.Fatalf("expected first request from IP to pass, reason=%s", res.Reason)
	}

	// Different API key, same source IP: should be denied by the IP bucket
	// even though "key2" has never made a request before (anti-evasion).
	res = s.Allow(AllowRequest{ClientKey: "key2", SourceIP: "1.2.3.4", Now: now})
	if res.Allowed {
		t.Fatalf("expected second request from same IP (different key) to be denied")
	}
	if res.Reason != "ip_limit" {
		t.Fatalf("expected reason ip_limit, got %s", res.Reason)
	}
}

func TestSchedulerWiringOnClientCreationAndEviction(t *testing.T) {
	now := time.Now()
	sched := newFakeScheduler()
	s := New(Options{MaxClients: 1, TierDefaults: testDefaults()})
	s.AttachScheduler(sched)

	s.Allow(AllowRequest{ClientKey: "a", Now: now})
	if !sched.has("a|default") {
		t.Fatalf("expected scheduler entry for a|default after client creation")
	}

	// Forcing eviction of "a" by adding "b" at capacity 1 should remove
	// its scheduler entry too.
	s.Allow(AllowRequest{ClientKey: "b", Now: now.Add(time.Second)})
	if sched.has("a|default") {
		t.Fatalf("expected scheduler entry for a|default to be removed on eviction")
	}
	if !sched.has("b|default") {
		t.Fatalf("expected scheduler entry for b|default after client creation")
	}
}

func TestBlockAndUnblock(t *testing.T) {
	now := time.Now()
	s := New(Options{MaxClients: 10, TierDefaults: testDefaults()})

	s.Block("alice", now)
	res := s.Allow(AllowRequest{ClientKey: "alice", Now: now})
	if res.Allowed {
		t.Fatalf("expected blocked client to be denied")
	}
	if res.Reason != "blocked" {
		t.Fatalf("expected reason blocked, got %s", res.Reason)
	}

	s.Unblock("alice")
	res = s.Allow(AllowRequest{ClientKey: "alice", Now: now})
	if !res.Allowed {
		t.Fatalf("expected unblocked client to be allowed, reason=%s", res.Reason)
	}
}

func TestConcurrentAllowDoesNotRace(t *testing.T) {
	now := time.Now()
	s := New(Options{MaxClients: 1000, TierDefaults: testDefaults()})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := "client"
			for j := 0; j < 20; j++ {
				s.Allow(AllowRequest{ClientKey: key, SourceIP: "1.1.1.1", Now: now})
			}
		}(i)
	}
	wg.Wait()
	// No assertion beyond "doesn't race/panic" -- run with `go test -race`.
}

func TestUpdateClientConfigChangesLimit(t *testing.T) {
	now := time.Now()
	s := New(Options{MaxClients: 10, TierDefaults: testDefaults()})

	s.UpdateClientConfig("alice", "", bucket.Config{MaxTokens: 1, RefillRate: 0, RefillInterval: 0}, now)

	res := s.Allow(AllowRequest{ClientKey: "alice", Now: now})
	if !res.Allowed {
		t.Fatalf("expected first request allowed, reason=%s", res.Reason)
	}
	res = s.Allow(AllowRequest{ClientKey: "alice", Now: now})
	if res.Allowed {
		t.Fatalf("expected second request denied after MaxTokens=1 reconfig")
	}
}
