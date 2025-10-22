package urlfilter_test

import (
	"runtime"
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/require"
)

// heapAlloc is a helper that returns the current heap-allocated bytes as
// counted by the runtime.
func heapAlloc() (heap float64) {
	m := runtime.MemStats{}
	runtime.ReadMemStats(&m)

	return float64(m.HeapAlloc)
}

// newTestRuleStorage is a helper that returns a new rule storage based on the
// given list ID and rule text and adds its Close method to tb's cleanup.
func newTestRuleStorage(tb testing.TB, id rules.ListID, text string) (s *filterlist.RuleStorage) {
	tb.Helper()

	list := filterlist.NewString(&filterlist.StringConfig{
		RulesText: text,
		ID:        id,
	})

	s, err := filterlist.NewRuleStorage([]filterlist.Interface{list})
	require.NoError(tb, err)

	testutil.CleanupAndRequireSuccess(tb, s.Close)

	return s
}
