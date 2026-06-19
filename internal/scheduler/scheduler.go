// Package scheduler implements the event-driven refill scheduler (FR4):
// rather than polling every bucket on a fixed tick, it maintains a min-heap
// of (id, nextRefillTime) pairs and sleeps exactly until the earliest due
// entry, waking early only when a new/updated schedule arrives.
//
// The scheduler is decoupled from the bucket/store/multibucket types: it
// only knows opaque string ids and a RefillFunc callback, which avoids an
// import cycle with internal/store (store imports scheduler's Scheduler
// interface locally, not the other way around).
package scheduler

import (
	"container/heap"
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// RefillFunc is invoked when an entry becomes due. It should perform the
// actual refill work for `id` and return the next time it should fire
// again, plus ok=false if the entry no longer exists (e.g. the client was
// evicted) and should not be rescheduled.
type RefillFunc func(id string, now time.Time) (next time.Time, ok bool)

// Scheduler is a single-goroutine, event-driven min-heap scheduler.
type Scheduler struct {
	mu      sync.Mutex
	h       refillHeap
	entries map[string]*refillEntry

	wakeup chan struct{} // buffered(1) signal to wake Run's sleep early

	onDue  RefillFunc
	logger *slog.Logger

	refillsTotal atomic.Int64
}

// New creates a Scheduler. Call Run in its own goroutine to start it.
func New(onDue RefillFunc, logger *slog.Logger) *Scheduler {
	s := &Scheduler{
		h:       make(refillHeap, 0),
		entries: make(map[string]*refillEntry),
		wakeup:  make(chan struct{}, 1),
		onDue:   onDue,
		logger:  logger,
	}
	heap.Init(&s.h)
	return s
}

// Schedule inserts a new entry or reschedules an existing one for id to
// fire at `next`. O(log n).
func (s *Scheduler) Schedule(id string, next time.Time) {
	s.mu.Lock()
	if e, ok := s.entries[id]; ok {
		e.nextRefillTime = next
		heap.Fix(&s.h, e.heapIndex)
	} else {
		e := &refillEntry{id: id, nextRefillTime: next}
		heap.Push(&s.h, e)
		s.entries[id] = e
	}
	s.mu.Unlock()
	s.signal()
}

// Remove cancels any pending schedule for id (e.g. on client eviction).
func (s *Scheduler) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return
	}
	heap.Remove(&s.h, e.heapIndex)
	delete(s.entries, id)
}

// signal wakes Run's sleep loop without blocking if a wakeup is already
// pending (coalescing is fine: Run always recomputes the true next-wake
// time from the heap on every iteration).
func (s *Scheduler) signal() {
	select {
	case s.wakeup <- struct{}{}:
	default:
	}
}

// Run blocks, processing due entries as they come up, until ctx is
// cancelled. It is event-driven: it sleeps until exactly the next due
// time, not on a fixed poll interval (NFR2.4).
func (s *Scheduler) Run(ctx context.Context) {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()

	for {
		wait := s.nextWait()

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)

		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			s.processDue()
		case <-s.wakeup:
			// A new/updated schedule arrived; loop around to recompute
			// the correct wait duration.
		}
	}
}

func (s *Scheduler) nextWait() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.h.Len() == 0 {
		return time.Hour
	}
	wait := time.Until(s.h[0].nextRefillTime)
	if wait < 0 {
		return 0
	}
	return wait
}

// processDue pops every entry whose nextRefillTime has arrived, invokes
// onDue for each, and reschedules those that report ok=true. Entries are
// removed from the map while being processed (decision D13) so that a
// concurrent Schedule() call for the same id during callback execution is
// treated as a fresh insert rather than colliding with a stale heap index.
func (s *Scheduler) processDue() {
	now := time.Now()

	var due []*refillEntry
	s.mu.Lock()
	for s.h.Len() > 0 && !s.h[0].nextRefillTime.After(now) {
		e := heap.Pop(&s.h).(*refillEntry)
		delete(s.entries, e.id)
		due = append(due, e)
	}
	s.mu.Unlock()

	for _, e := range due {
		next, ok := s.onDue(e.id, now)
		s.refillsTotal.Add(1)
		if ok {
			s.Schedule(e.id, next)
		}
	}
}

// HeapSize reports the current number of scheduled entries, for metrics.
func (s *Scheduler) HeapSize() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.h.Len()
}

// RefillsTotal reports the cumulative number of due-entry callbacks
// processed, for metrics.
func (s *Scheduler) RefillsTotal() int64 {
	return s.refillsTotal.Load()
}
