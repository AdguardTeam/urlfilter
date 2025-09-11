package filterlist_test

import (
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuleStorage(t *testing.T) {
	t.Parallel()

	list1 := filterlist.NewString(&filterlist.StringConfig{
		RulesText: testRuleText,
		ID:        testListID,
	})

	list2 := filterlist.NewString(&filterlist.StringConfig{
		RulesText: testRuleTextOther,
		ID:        testListIDOther,
	})

	// Create storage from two lists.
	storage, err := filterlist.NewRuleStorage([]filterlist.Interface{list1, list2})
	require.NoError(t, err)

	// Create a scanner instance.
	scanner := storage.NewRuleStorageScanner()
	assert.NotNil(t, scanner)

	// Time to scan!

	// Rule 1 from the list 1
	assert.True(t, scanner.Scan())
	f, id := scanner.Rule()

	assert.NotNil(t, f)
	assert.Equal(t, testRuleDomain, f.Text())
	assert.Equal(t, testListID, f.GetFilterListID())
	assert.Equal(t, testStrgID1Rule1, id)

	// Rule 2 from the list 1.
	assert.True(t, scanner.Scan())
	f, id = scanner.Rule()

	assert.NotNil(t, f)
	assert.Equal(t, testRuleCosmetic, f.Text())
	assert.Equal(t, testListID, f.GetFilterListID())
	assert.Equal(t, testStrgID1Rule2, id)

	// Rule 1 from the list 2.
	assert.True(t, scanner.Scan())
	f, id = scanner.Rule()

	assert.NotNil(t, f)
	assert.Equal(t, "||example.com", f.Text())
	assert.Equal(t, testListIDOther, f.GetFilterListID())
	assert.Equal(t, testStrgID2Rule1, id)

	// Rule 2 from the list 2.
	assert.True(t, scanner.Scan())
	f, id = scanner.Rule()

	assert.NotNil(t, f)
	assert.Equal(t, "##advert", f.Text())
	assert.Equal(t, testListIDOther, f.GetFilterListID())
	assert.Equal(t, testStrgID2Rule2, id)

	// Now check that there's nothing to read.
	assert.False(t, scanner.Scan())

	// Check that nothing breaks if we read a finished scanner.
	assert.False(t, scanner.Scan())

	// Time to retrieve!

	// Rule 1 from the list 1.
	f, err = storage.RetrieveRule(testStrgID1Rule1)
	require.NoError(t, err)
	assert.NotNil(t, f)
	assert.Equal(t, testRuleDomain, f.Text())

	// Rule 2 from the list 1.
	f, err = storage.RetrieveRule(testStrgID1Rule2)
	require.NoError(t, err)
	assert.NotNil(t, f)
	assert.Equal(t, testRuleCosmetic, f.Text())

	// Rule 1 from the list 2.
	f, err = storage.RetrieveRule(testStrgID2Rule1)
	require.NoError(t, err)
	assert.NotNil(t, f)
	assert.Equal(t, "||example.com", f.Text())

	// Rule 2 from the list 2.
	f, err = storage.RetrieveRule(testStrgID2Rule2)
	require.NoError(t, err)
	assert.NotNil(t, f)
	assert.Equal(t, "##advert", f.Text())
}

func TestRuleStorage_invalid(t *testing.T) {
	t.Parallel()

	conf := &filterlist.StringConfig{
		ID:        testListID,
		RulesText: "",
	}
	_, err := filterlist.NewRuleStorage([]filterlist.Interface{
		filterlist.NewString(conf),
		filterlist.NewString(conf),
	})
	testutil.AssertErrorMsg(t, "at index 1: id: duplicated value: '\\x01'", err)
}

func BenchmarkStorage_RetrieveRule(b *testing.B) {
	l1 := filterlist.NewString(&filterlist.StringConfig{
		RulesText: testRuleText,
		ID:        testListID,
	})

	l2 := filterlist.NewString(&filterlist.StringConfig{
		RulesText: testRuleTextOther,
		ID:        testListIDOther,
	})

	s, consErr := filterlist.NewRuleStorage([]filterlist.Interface{l1, l2})
	require.NoError(b, consErr)

	require.True(b, b.Run("cached", func(b *testing.B) {
		// Warmup to fill the cache.
		r, err := s.RetrieveRule(testStrgID2Rule2)

		b.ReportAllocs()
		for b.Loop() {
			r, err = s.RetrieveRule(testStrgID2Rule2)
		}

		require.Nil(b, err)
		require.NotNil(b, r)
	}))

	require.True(b, b.Run("no_cache", func(b *testing.B) {
		s.DisableCache()

		var r rules.Rule
		var err error

		b.ReportAllocs()
		for b.Loop() {
			r, err = s.RetrieveRule(testStrgID2Rule2)
		}

		require.Nil(b, err)
		require.NotNil(b, r)
	}))

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter/filterlist
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkStorage_RetrieveRule/cached-16         	81577381	        13.93 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkStorage_RetrieveRule/no_cache-16       	 3115383	       370.8 ns/op	      96 B/op	       1 allocs/op
}
