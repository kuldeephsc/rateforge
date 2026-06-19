package scheduler

import "time"

// refillEntry is one item in the scheduler's min-heap, ordered by
// nextRefillTime. heapIndex is maintained by the heap implementation so
// that Schedule() can find and fix an existing entry in O(log n) instead
// of needing a linear scan.
type refillEntry struct {
	id             string
	nextRefillTime time.Time
	heapIndex      int
}

// refillHeap implements container/heap.Interface over a slice of
// *refillEntry, ordered so the entry with the earliest nextRefillTime is
// always at index 0 (Peek/Extract are O(1)/O(log n) respectively, per
// NFR2.2).
type refillHeap []*refillEntry

func (h refillHeap) Len() int { return len(h) }

func (h refillHeap) Less(i, j int) bool {
	return h[i].nextRefillTime.Before(h[j].nextRefillTime)
}

func (h refillHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapIndex = i
	h[j].heapIndex = j
}

func (h *refillHeap) Push(x any) {
	entry := x.(*refillEntry)
	entry.heapIndex = len(*h)
	*h = append(*h, entry)
}

func (h *refillHeap) Pop() any {
	old := *h
	n := len(old)
	entry := old[n-1]
	old[n-1] = nil // avoid retaining a reference
	entry.heapIndex = -1
	*h = old[:n-1]
	return entry
}
