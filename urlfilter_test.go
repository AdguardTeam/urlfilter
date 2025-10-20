package urlfilter_test

import "runtime"

// heapAlloc is a helper that returns the current heap-allocated bytes as
// counted by the runtime.
func heapAlloc() (heap float64) {
	m := runtime.MemStats{}
	runtime.ReadMemStats(&m)

	return float64(m.HeapAlloc)
}
