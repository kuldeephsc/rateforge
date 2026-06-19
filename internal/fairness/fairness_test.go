package fairness

import "testing"

func TestDisabledTrackerIsNoOp(t *testing.T) {
	tr := New(false, 1.0)
	if tr.Enabled() {
		t.Fatalf("expected disabled tracker")
	}
	if got := tr.RecordConsumption("a", 100); got != 0 {
		t.Fatalf("expected no-op RecordConsumption on disabled tracker, got %v", got)
	}
	snap := tr.Snapshot()
	if len(snap) != 0 {
		t.Fatalf("expected empty snapshot on disabled tracker")
	}
}

func TestHigherWeightLowerPriorityValue(t *testing.T) {
	tr := New(true, 1.0)
	tr.SetWeight("heavy", 10.0) // high weight = gets more capacity per virtual-time unit
	tr.SetWeight("light", 1.0)

	tr.RecordConsumption("heavy", 100)
	tr.RecordConsumption("light", 100)

	heavyPriority := tr.Priority("heavy")
	lightPriority := tr.Priority("light")

	if heavyPriority >= lightPriority {
		t.Fatalf("expected heavy-weight client to have lower virtual finish time: heavy=%v light=%v", heavyPriority, lightPriority)
	}
}

func TestSnapshotTracksCumulativeConsumption(t *testing.T) {
	tr := New(true, 1.0)
	tr.RecordConsumption("a", 5)
	tr.RecordConsumption("a", 3)
	tr.RecordConsumption("b", 7)

	snap := tr.Snapshot()
	if snap["a"] != 8 {
		t.Fatalf("expected a=8, got %d", snap["a"])
	}
	if snap["b"] != 7 {
		t.Fatalf("expected b=7, got %d", snap["b"])
	}
}

func TestNilTrackerIsSafe(t *testing.T) {
	var tr *Tracker
	if tr.Enabled() {
		t.Fatalf("expected nil tracker to report disabled")
	}
	if got := tr.RecordConsumption("a", 5); got != 0 {
		t.Fatalf("expected nil tracker RecordConsumption to be a no-op")
	}
	if got := tr.Priority("a"); got != 0 {
		t.Fatalf("expected nil tracker Priority to be 0")
	}
	_ = tr.Snapshot()
}
