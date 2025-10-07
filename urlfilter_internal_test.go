package urlfilter

import (
	"runtime"
	"testing"
)

// heapAlloc is a helper that returns the current heap-allocated bytes as
// counted by the runtime.
func heapAlloc(tb testing.TB) (heap float64) {
	tb.Helper()

	m := runtime.MemStats{}
	runtime.ReadMemStats(&m)

	return float64(m.HeapAlloc)
}
