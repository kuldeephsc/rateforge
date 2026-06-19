// Package metrics implements a minimal, zero-dependency Prometheus
// text-exposition-format metrics registry.
//
// NOTE ON THE ZERO-DEPENDENCY CHOICE: the sandbox this was built in had no
// network access to `go get` github.com/prometheus/client_golang, so this
// package hand-rolls just enough of the exposition format (counters,
// gauges, and a fixed-bucket histogram) to satisfy design.md's metrics
// table. It deliberately does not attempt to replicate the full Prometheus
// client library's API surface (no vector types, no full HELP/TYPE
// validation beyond what's needed here). Swap for the real client library
// once you have network access, if you want a richer feature set; the
// Registry type's exported field names were chosen to make that swap
// mechanical.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Counter is a monotonically-increasing value, optionally sharded by a
// single label (e.g. "decision" with values "allow"/"reject").
type Counter struct {
	name string
	help string
	mu   sync.RWMutex
	vals map[string]*atomic.Int64 // label value -> count
}

func newCounter(name, help string) *Counter {
	return &Counter{name: name, help: help, vals: make(map[string]*atomic.Int64)}
}

// Inc increments the counter for the given label value (use "" if the
// counter has no label).
func (c *Counter) Inc(label string) {
	c.mu.RLock()
	v, ok := c.vals[label]
	c.mu.RUnlock()
	if ok {
		v.Add(1)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok = c.vals[label]; ok {
		v.Add(1)
		return
	}
	v = &atomic.Int64{}
	v.Store(1)
	c.vals[label] = v
}

func (c *Counter) write(b *strings.Builder, labelName string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n", c.name, c.help, c.name)
	c.mu.RLock()
	defer c.mu.RUnlock()
	labels := make([]string, 0, len(c.vals))
	for l := range c.vals {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	for _, l := range labels {
		if l == "" || labelName == "" {
			fmt.Fprintf(b, "%s %d\n", c.name, c.vals[l].Load())
		} else {
			fmt.Fprintf(b, "%s{%s=%q} %d\n", c.name, labelName, l, c.vals[l].Load())
		}
	}
}

// Gauge is a value that can go up or down.
type Gauge struct {
	name string
	help string
	v    atomic.Int64
}

func newGauge(name, help string) *Gauge { return &Gauge{name: name, help: help} }

// Set sets the gauge's current value.
func (g *Gauge) Set(v int64) { g.v.Store(v) }

// Add adjusts the gauge's current value by delta (which may be negative).
func (g *Gauge) Add(delta int64) { g.v.Add(delta) }

func (g *Gauge) write(b *strings.Builder) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", g.name, g.help, g.name, g.name, g.v.Load())
}

// histogramBuckets are the fixed upper bounds (seconds) used for latency
// histograms, chosen to give useful resolution around the NFR1.1 <50us p99
// target while still covering slow outliers up to 1s.
var histogramBuckets = []float64{0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1}

// Histogram is a fixed-bucket latency histogram (Prometheus exposition
// format: one counter per bucket upper bound, plus _sum and _count).
type Histogram struct {
	name    string
	help    string
	mu      sync.Mutex
	buckets []int64 // cumulative counts, parallel to histogramBuckets
	sum     float64
	count   int64
}

func newHistogram(name, help string) *Histogram {
	return &Histogram{name: name, help: help, buckets: make([]int64, len(histogramBuckets))}
}

// Observe records one latency sample, in seconds.
func (h *Histogram) Observe(seconds float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sum += seconds
	h.count++
	for i, upper := range histogramBuckets {
		if seconds <= upper {
			h.buckets[i]++
		}
	}
}

func (h *Histogram) write(b *strings.Builder) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s histogram\n", h.name, h.help, h.name)
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, upper := range histogramBuckets {
		fmt.Fprintf(b, "%s_bucket{le=%q} %d\n", h.name, strconv.FormatFloat(upper, 'f', -1, 64), h.buckets[i])
	}
	fmt.Fprintf(b, "%s_bucket{le=\"+Inf\"} %d\n", h.name, h.count)
	fmt.Fprintf(b, "%s_sum %v\n", h.name, h.sum)
	fmt.Fprintf(b, "%s_count %d\n", h.name, h.count)
}

// Registry holds every metric Sentinel exposes (design.md's metrics table).
type Registry struct {
	RequestsTotal     *Counter // label: decision = "allow" | "reject"
	RequestLatency    *Histogram
	ActiveClients     *Gauge
	SchedulerRefills  *Gauge
	SchedulerHeapSize *Gauge
	EvictionsTotal    *Gauge
	AdminChangesTotal *Counter // label: action

	// decisionLabel/actionLabel record which label name each counter uses,
	// purely so Handler can emit the right label key without hardcoding it
	// twice.
	decisionLabel string
	actionLabel   string
}

// NewRegistry constructs a Registry with all metrics pre-created.
func NewRegistry() *Registry {
	return &Registry{
		RequestsTotal:     newCounter("sentinel_requests_total", "Total rate-limit decisions made."),
		RequestLatency:    newHistogram("sentinel_request_latency_seconds", "Decision latency in seconds."),
		ActiveClients:     newGauge("sentinel_active_clients", "Number of currently tracked clients."),
		SchedulerRefills:  newGauge("sentinel_scheduler_refills_total", "Cumulative scheduled refills processed."),
		SchedulerHeapSize: newGauge("sentinel_scheduler_heap_size", "Current number of scheduled refill entries."),
		EvictionsTotal:    newGauge("sentinel_evictions_total", "Cumulative LRU client evictions."),
		AdminChangesTotal: newCounter("sentinel_admin_changes_total", "Total admin API mutations."),
		decisionLabel:     "decision",
		actionLabel:       "action",
	}
}

// Handler returns an http.Handler that serves the registry in Prometheus
// text exposition format on GET requests.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var b strings.Builder
		r.RequestsTotal.write(&b, r.decisionLabel)
		r.RequestLatency.write(&b)
		r.ActiveClients.write(&b)
		r.SchedulerRefills.write(&b)
		r.SchedulerHeapSize.write(&b)
		r.EvictionsTotal.write(&b)
		r.AdminChangesTotal.write(&b, r.actionLabel)

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(b.String()))
	})
}
