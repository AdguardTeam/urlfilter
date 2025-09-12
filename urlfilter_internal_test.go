package urlfilter

import (
	"runtime"
	"testing"

	"github.com/AdguardTeam/urlfilter/rules"
)

// Common ListIDs for tests.
const (
	testListID      rules.ListID = 1
	testListIDOther rules.ListID = 2
)

// heapAlloc is a helper that returns the current heap-allocated bytes as
// counted by the runtime.
func heapAlloc(tb testing.TB) (heap float64) {
	tb.Helper()

	m := runtime.MemStats{}
	runtime.ReadMemStats(&m)

	return float64(m.HeapAlloc)
}
