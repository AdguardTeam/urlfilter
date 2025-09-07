package filterlist_test

import (
	"path/filepath"
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testFileRuleList is a path to the test file rule list.
var testFileRuleList = filepath.Join(testResourcesDir, "test_file_rule_list.txt")

func TestFile_RuleListScanner(t *testing.T) {
	t.Parallel()

	ruleList, err := filterlist.NewFile(&filterlist.FileConfig{
		Path: testFileRuleList,
		ID:   testListID,
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, ruleList.Close)
	assert.Equal(t, testListID, ruleList.GetID())

	scanner := ruleList.NewScanner()
	assert.True(t, scanner.Scan())

	f, idx := scanner.Rule()
	require.NotNil(t, f)

	assert.Equal(t, "||example.org", f.Text())
	assert.Equal(t, testListID, f.GetFilterListID())
	assert.Equal(t, 0, idx)

	assert.True(t, scanner.Scan())

	f, idx = scanner.Rule()
	require.NotNil(t, f)

	assert.Equal(t, testRuleCosmetic, f.Text())
	assert.Equal(t, testListID, f.GetFilterListID())
	assert.Equal(t, 21, idx)

	// Finish scanning.
	assert.False(t, scanner.Scan())

	f, err = ruleList.RetrieveRule(0)
	require.NoError(t, err)
	require.NotNil(t, f)

	assert.Equal(t, "||example.org", f.Text())
	assert.Equal(t, testListID, f.GetFilterListID())

	f, err = ruleList.RetrieveRule(21)
	require.NoError(t, err)
	require.NotNil(t, f)

	assert.Equal(t, testRuleCosmetic, f.Text())
	assert.Equal(t, testListID, f.GetFilterListID())
}

func BenchmarkFile_RetrieveRule(b *testing.B) {
	conf := &filterlist.FileConfig{
		Path: testFileRuleList,
		ID:   testListID,
	}

	f, fileErr := filterlist.NewFile(conf)
	require.NoError(b, fileErr)
	testutil.CleanupAndRequireSuccess(b, f.Close)

	var r rules.Rule
	var err error

	b.ReportAllocs()
	for b.Loop() {
		r, err = f.RetrieveRule(0)
	}

	assert.Nil(b, err)
	assert.NotZero(b, r)

	// Most recent results:
	//
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/urlfilter/filterlist
	//	cpu: Apple M1 Pro
	//	BenchmarkFile_RetrieveRule-8   	  995864	      1173 ns/op	     448 B/op	       4 allocs/op
}
