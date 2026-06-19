// Package fairness implements an advisory weighted-fair-queuing tracker
// (bonus requirement B4).
//
// IMPORTANT SCOPE NOTE: Go's net/http server model hands each request its
// own goroutine with no central admission queue, so there is no point at
// which Sentinel can actually reorder or delay one client's request behind
// another's without adding a bespoke queuing layer in front of net/http
// (out of scope for this build). This Tracker therefore implements the
// spec's virtual-finish-time bookkeeping faithfully and exposes it via the
// admin API (GET /admin/v1/fairness) for observability and for future use
// by a real scheduler, but it does NOT currently influence request
// ordering. This is called out explicitly in README.md.
package fairness

import "sync"

// Tracker records per-client consumption and computes virtual finish times
// using the standard WFQ formula: virtualFinish = virtualTime +
// consumed/weight.
type Tracker struct {
	mu      sync.RWMutex
	enabled bool

	consumption   map[string]int64
	weights       map[string]float64
	defaultWeight float64
	virtualTime   float64
}

// New creates a Tracker. If enabled is false, RecordConsumption and
// Priority become no-ops (zero values), so callers do not need to branch
// on enabled themselves.
func New(enabled bool, defaultWeight float64) *Tracker {
	if defaultWeight <= 0 {
		defaultWeight = 1.0
	}
	return &Tracker{
		enabled:       enabled,
		consumption:   make(map[string]int64),
		weights:       make(map[string]float64),
		defaultWeight: defaultWeight,
	}
}

// Enabled reports whether fairness tracking is active.
func (t *Tracker) Enabled() bool {
	if t == nil {
		return false
	}
	return t.enabled
}

// SetWeight assigns a client-specific weight (higher weight => lower
// virtual finish time for the same consumption => effectively higher
// priority were a real scheduler consuming this data).
func (t *Tracker) SetWeight(clientKey string, weight float64) {
	if t == nil || !t.enabled || weight <= 0 {
		return
	}
	t.mu.Lock()
	t.weights[clientKey] = weight
	t.mu.Unlock()
}

// RecordConsumption records that clientKey consumed `tokens` worth of
// capacity and returns its updated virtual finish time.
func (t *Tracker) RecordConsumption(clientKey string, tokens int64) float64 {
	if t == nil || !t.enabled {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	weight := t.weights[clientKey]
	if weight <= 0 {
		weight = t.defaultWeight
	}

	t.consumption[clientKey] += tokens
	t.virtualTime += float64(tokens) / weight

	return t.virtualTime + float64(t.consumption[clientKey])/weight
}

// Priority returns a client's current virtual finish time without
// recording new consumption. Lower values indicate the client is "behind"
// relative to its fair share and would be prioritized by a real scheduler.
func (t *Tracker) Priority(clientKey string) float64 {
	if t == nil || !t.enabled {
		return 0
	}
	t.mu.RLock()
	defer t.mu.RUnlock()

	weight := t.weights[clientKey]
	if weight <= 0 {
		weight = t.defaultWeight
	}
	return t.virtualTime + float64(t.consumption[clientKey])/weight
}

// Snapshot returns a copy of cumulative per-client consumption, for the
// admin fairness-status endpoint.
func (t *Tracker) Snapshot() map[string]int64 {
	out := make(map[string]int64)
	if t == nil || !t.enabled {
		return out
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	for k, v := range t.consumption {
		out[k] = v
	}
	return out
}
