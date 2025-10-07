package filterlist_test

import (
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/internal/uftest"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBytes_RuleListScanner(t *testing.T) {
	t.Parallel()

	conf := &filterlist.BytesConfig{
		RulesText: []byte(testRuleText),
		ID:        uftest.ListID1,
	}

	ruleList := filterlist.NewBytes(conf)
	testutil.CleanupAndRequireSuccess(t, ruleList.Close)
	assert.Equal(t, uftest.ListID1, ruleList.ListID())

	scanner := ruleList.NewScanner()
	assert.True(t, scanner.Scan())

	f, idx := scanner.Rule()
	require.NotNil(t, f)

	assert.Equal(t, uftest.RuleHost, f.Text())
	assert.Equal(t, uftest.ListID1, f.GetFilterListID())
	assert.Equal(t, int64(0), idx)

	assert.True(t, scanner.Scan())

	f, idx = scanner.Rule()
	require.NotNil(t, f)

	assert.Equal(t, testRuleCosmetic, f.Text())
	assert.Equal(t, uftest.ListID1, f.GetFilterListID())
	assert.Equal(t, cosmeticRuleIndex, idx)

	// Finish scanning.
	assert.False(t, scanner.Scan())

	f, err := ruleList.RetrieveRule(0)
	require.NoError(t, err)
	require.NotNil(t, f)

	assert.Equal(t, uftest.RuleHost, f.Text())
	assert.Equal(t, uftest.ListID1, f.GetFilterListID())

	f, err = ruleList.RetrieveRule(cosmeticRuleIndex)
	require.NoError(t, err)
	require.NotNil(t, f)

	assert.Equal(t, testRuleCosmetic, f.Text())
	assert.Equal(t, uftest.ListID1, f.GetFilterListID())
}

func BenchmarkBytes_RetrieveRule(b *testing.B) {
	conf := &filterlist.BytesConfig{
		RulesText: []byte(testRuleText),
		ID:        uftest.ListID1,
	}

	s := filterlist.NewBytes(conf)
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
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter/filterlist
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkBytes_RetrieveRule-16  	 2301092	       508.1 ns/op	     448 B/op	       4 allocs/op
}
