package filterlist_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/internal/uftest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testFileRuleList is a path to the test file rule list.
var testFileRuleList = filepath.Join(testResourcesDir, "test_file_rule_list.txt")

func TestFile_RuleListScanner(t *testing.T) {
	t.Parallel()

	ruleList, err := filterlist.NewFile(&filterlist.FileConfig{
		Path: testFileRuleList,
		ID:   uftest.ListID1,
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, ruleList.Close)
	assert.Equal(t, uftest.ListID1, ruleList.ListID())

	scanner := ruleList.NewScanner()
	assert.True(t, scanner.Scan())

	f, idx := scanner.Rule()
	require.NotNil(t, f)

	assert.Equal(t, "||example.org", f.Text())
	assert.Equal(t, uftest.ListID1, f.GetFilterListID())
	assert.Equal(t, int64(0), idx)

	assert.True(t, scanner.Scan())

	f, idx = scanner.Rule()
	require.NotNil(t, f)

	assert.Equal(t, testRuleCosmetic, f.Text())
	assert.Equal(t, uftest.ListID1, f.GetFilterListID())
	assert.Equal(t, int64(21), idx)

	// Finish scanning.
	assert.False(t, scanner.Scan())

	f, err = ruleList.RetrieveRule(0)
	require.NoError(t, err)
	require.NotNil(t, f)

	assert.Equal(t, "||example.org", f.Text())
	assert.Equal(t, uftest.ListID1, f.GetFilterListID())

	f, err = ruleList.RetrieveRule(21)
	require.NoError(t, err)
	require.NotNil(t, f)

	assert.Equal(t, testRuleCosmetic, f.Text())
	assert.Equal(t, uftest.ListID1, f.GetFilterListID())
}

func TestFile_RetrieveRule_longAndEOF(t *testing.T) {
	t.Parallel()

	// Build a rule longer than the 4 KiB read buffer followed by a final rule
	// with no trailing newline.
	longRule := "||" + strings.Repeat("a", 5000) + ".example^"
	eofRule := "||eof.example^"
	content := longRule + "\n" + eofRule

	p := filepath.Join(t.TempDir(), "rules.txt")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))

	fl, err := filterlist.NewFile(&filterlist.FileConfig{
		Path: p,
		ID:   uftest.ListID1,
	})
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, fl.Close)

	r1, err := fl.RetrieveRule(0)
	require.NoError(t, err)
	assert.Equal(t, longRule, r1.Text())

	r2, err := fl.RetrieveRule(int64(len(longRule) + 1))
	require.NoError(t, err)
	assert.Equal(t, eofRule, r2.Text())
}

func BenchmarkFile_RetrieveRule(b *testing.B) {
	conf := &filterlist.FileConfig{
		Path: testFileRuleList,
		ID:   uftest.ListID1,
	}

	f, fileErr := filterlist.NewFile(conf)
	require.NoError(b, fileErr)
	testutil.CleanupAndRequireSuccess(b, f.Close)

	// Warmup to fill the buffer.
	r, err := f.RetrieveRule(0)
	require.NoError(b, err)

	b.ReportAllocs()
	for b.Loop() {
		r, err = f.RetrieveRule(0)
	}

	require.NoError(b, err)
	assert.NotNil(b, r)

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/urlfilter/filterlist
	//	cpu: Apple M1 Pro
	//  BenchmarkFile_RetrieveRule-8   	  970134	      1218 ns/op	     448 B/op	       4 allocs/op
}
