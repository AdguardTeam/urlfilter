package filterlist_test

import (
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestString_RuleListScanner(t *testing.T) {
	t.Parallel()

	conf := &filterlist.StringConfig{
		RulesText: testRuleText,
		ID:        testListID,
	}

	ruleList := filterlist.NewString(conf)
	testutil.CleanupAndRequireSuccess(t, ruleList.Close)
	assert.Equal(t, testListID, ruleList.GetID())

	scanner := ruleList.NewScanner()
	assert.True(t, scanner.Scan())

	f, idx := scanner.Rule()
	require.NotNil(t, f)

	assert.Equal(t, testRuleDomain, f.Text())
	assert.Equal(t, testListID, f.GetFilterListID())
	assert.Equal(t, 0, idx)

	assert.True(t, scanner.Scan())

	f, idx = scanner.Rule()
	require.NotNil(t, f)

	assert.Equal(t, testRuleCosmetic, f.Text())
	assert.Equal(t, testListID, f.GetFilterListID())
	assert.Equal(t, cosmeticRuleIndex, idx)

	// Finish scanning.
	assert.False(t, scanner.Scan())

	f, err := ruleList.RetrieveRule(0)
	require.NoError(t, err)
	require.NotNil(t, f)

	assert.Equal(t, testRuleDomain, f.Text())
	assert.Equal(t, testListID, f.GetFilterListID())

	f, err = ruleList.RetrieveRule(cosmeticRuleIndex)
	require.NoError(t, err)
	require.NotNil(t, f)

	assert.Equal(t, testRuleCosmetic, f.Text())
	assert.Equal(t, testListID, f.GetFilterListID())
}

func BenchmarkString_RetrieveRule(b *testing.B) {
	conf := &filterlist.StringConfig{
		RulesText: testRuleText,
		ID:        testListID,
	}

	s := filterlist.NewString(conf)
	testutil.CleanupAndRequireSuccess(b, s.Close)

	var r rules.Rule
	var err error

	b.ReportAllocs()
	for b.Loop() {
		r, err = s.RetrieveRule(0)
	}

	assert.Nil(b, err)
	assert.NotZero(b, r)

	// Most recent results:
	//
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/urlfilter/filterlist
	//	cpu: Apple M1 Pro
	//	BenchmarkString_RetrieveRule-8   	 6182457	       185.4 ns/op	     432 B/op	       3 allocs/op
}
