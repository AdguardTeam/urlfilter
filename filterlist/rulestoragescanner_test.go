package filterlist_test

import (
	"strings"
	"testing"

	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuleStorageScanner(t *testing.T) {
	t.Parallel()

	l1 := strings.NewReader(testRuleText)
	l2 := strings.NewReader(testRuleTextOther)

	s1 := filterlist.NewRuleScanner(l1, testListID, false)
	s2 := filterlist.NewRuleScanner(l2, testListIDOther, false)

	// Now create the storage scanner.
	storageScanner := &filterlist.RuleStorageScanner{
		Scanners: []*filterlist.RuleScanner{s1, s2},
	}

	// Rule 1 from the list 1.
	assert.True(t, storageScanner.Scan())
	f, id := storageScanner.Rule()

	assert.NotNil(t, f)
	assert.Equal(t, testRuleDomain, f.Text())
	assert.Equal(t, testListID, f.GetFilterListID())
	assert.Equal(t, testStrgID1Rule1, id)

	// Rule 2 from the list 1.
	assert.True(t, storageScanner.Scan())
	f, id = storageScanner.Rule()

	assert.NotNil(t, f)
	assert.Equal(t, testRuleCosmetic, f.Text())
	assert.Equal(t, testListID, f.GetFilterListID())
	assert.Equal(t, testStrgID1Rule2, id)

	// Rule 1 from the list 2.
	assert.True(t, storageScanner.Scan())
	f, id = storageScanner.Rule()

	assert.NotNil(t, f)
	assert.Equal(t, "||example.com", f.Text())
	assert.Equal(t, testListIDOther, f.GetFilterListID())
	assert.Equal(t, testStrgID2Rule1, id)

	// Rule 2 from the list 2.
	assert.True(t, storageScanner.Scan())
	f, id = storageScanner.Rule()

	assert.NotNil(t, f)
	assert.Equal(t, "##advert", f.Text())
	assert.Equal(t, testListIDOther, f.GetFilterListID())
	assert.Equal(t, testStrgID2Rule2, id)

	// Now check that there's nothing to read.
	assert.False(t, storageScanner.Scan())

	// Check that nothing breaks if we read a finished scanner.
	assert.False(t, storageScanner.Scan())
}

func BenchmarkRuleStorageScanner_Scan(b *testing.B) {
	r1 := strings.NewReader(testRuleText)
	r2 := strings.NewReader(testRuleTextOther)

	s1 := filterlist.NewRuleScanner(r1, testListID, false)
	s2 := filterlist.NewRuleScanner(r2, testListIDOther, false)

	s := &filterlist.RuleStorageScanner{
		Scanners: []*filterlist.RuleScanner{s1, s2},
	}

	var rule rules.Rule
	b.ReportAllocs()
	for b.Loop() {
		for s.Scan() {
			rule, _ = s.Rule()
		}
	}

	require.NotNil(b, rule)

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter/filterlist
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkRuleStorageScanner_Scan-16    	18721648	        64.49 ns/op	       0 B/op	       0 allocs/op
}
