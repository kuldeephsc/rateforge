package scheduler

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestScheduleAndFireOrdering(t *testing.T) {
	var mu sync.Mutex
	var fired []string

	onDue := func(id string, now time.Time) (time.Time, bool) {
		mu.Lock()
		fired = append(fired, id)
		mu.Unlock()
		return time.Time{}, false // do not reschedule
	}

	s := New(onDue, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	now := time.Now()
	s.Schedule("c", now.Add(30*time.Millisecond))
	s.Schedule("a", now.Add(10*time.Millisecond))
	s.Schedule("b", now.Add(20*time.Millisecond))

	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		n := len(fired)
		mu.Unlock()
		if n >= 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for all entries to fire, got %v", fired)
		case <-time.After(5 * time.Millisecond):
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(fired) != 3 {
		t.Fatalf("expected 3 fired entries, got %d: %v", len(fired), fired)
	}
	if fired[0] != "a" || fired[1] != "b" || fired[2] != "c" {
		t.Fatalf("expected fire order a,b,c got %v", fired)
	}
}

func TestRescheduleViaFix(t *testing.T) {
	var mu sync.Mutex
	count := 0

	onDue := func(id string, now time.Time) (time.Time, bool) {
		mu.Lock()
		count++
		c := count
		mu.Unlock()
		if c < 3 {
			return now.Add(5 * time.Millisecond), true
		}
		return time.Time{}, false
	}

	s := New(onDue, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	s.Schedule("x", time.Now().Add(5*time.Millisecond))

	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		c := count
		mu.Unlock()
		if c >= 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for reschedules, got count=%d", c)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestRemoveCancelsSchedule(t *testing.T) {
	var mu sync.Mutex
	fired := false

	onDue := func(id string, now time.Time) (time.Time, bool) {
		mu.Lock()
		fired = true
		mu.Unlock()
		return time.Time{}, false
	}

	s := New(onDue, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	s.Schedule("y", time.Now().Add(50*time.Millisecond))
	s.Remove("y")

	time.Sleep(150 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if fired {
		t.Fatalf("expected removed entry not to fire")
	}
}

func TestHeapSizeReflectsScheduledEntries(t *testing.T) {
	onDue := func(id string, now time.Time) (time.Time, bool) {
		return time.Time{}, false
	}
	s := New(onDue, nil)

	s.Schedule("a", time.Now().Add(time.Hour))
	s.Schedule("b", time.Now().Add(time.Hour))
	if got := s.HeapSize(); got != 2 {
		t.Fatalf("expected heap size 2, got %d", got)
	}

	s.Remove("a")
	if got := s.HeapSize(); got != 1 {
		t.Fatalf("expected heap size 1 after remove, got %d", got)
	}
}
