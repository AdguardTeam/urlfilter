package urlfilter_test

import (
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCosmeticEngine_Match_elementHiding(t *testing.T) {
	t.Parallel()

	engine := newTestCosmeticEngine(t)

	result := engine.Match("example.org", true, true, true)
	require.NotNil(t, result)

	assert.Equal(t, urlfilter.StylesResult{
		Generic:        []string{"banner_generic"},
		Specific:       []string{"banner_specific"},
		GenericExtCSS:  nil,
		SpecificExtCSS: nil,
	}, result.ElementHiding)
}

func TestCosmeticEngine_Match_elementHidingNoDisabled(t *testing.T) {
	t.Parallel()

	engine := newTestCosmeticEngine(t)

	result := engine.Match("example.com", true, true, true)
	require.NotNil(t, result)

	assert.Equal(t, urlfilter.StylesResult{
		Generic:        []string{"banner_generic", "banner_generic_disabled"},
		Specific:       nil,
		GenericExtCSS:  nil,
		SpecificExtCSS: nil,
	}, result.ElementHiding)
}

func TestCosmeticEngine_Match_elementHidingNoGeneric(t *testing.T) {
	t.Parallel()

	engine := newTestCosmeticEngine(t)

	result := engine.Match("example.org", true, true, false)
	require.NotNil(t, result)

	assert.Equal(t, urlfilter.StylesResult{
		Generic:        nil,
		Specific:       []string{"banner_specific"},
		GenericExtCSS:  nil,
		SpecificExtCSS: nil,
	}, result.ElementHiding)
}

func TestCosmeticEngine_Match_elementHidingNoCSS(t *testing.T) {
	t.Parallel()

	engine := newTestCosmeticEngine(t)

	result := engine.Match("example.org", false, true, true)
	require.NotNil(t, result)

	assert.Equal(t, urlfilter.StylesResult{
		Generic:        nil,
		Specific:       nil,
		GenericExtCSS:  nil,
		SpecificExtCSS: nil,
	}, result.ElementHiding)
}

func FuzzCosmeticEngine_Match(f *testing.F) {
	for _, seed := range []string{
		"",
		" ",
		"\n",
		"1",
		"127.0.0.1",
		"example.test",
	} {
		f.Add(seed)
	}

	engine := newTestCosmeticEngine(f)

	f.Fuzz(func(t *testing.T, host string) {
		assert.NotPanics(t, func() {
			_ = engine.Match(host, true, true, true)
		})
	})
}

// newTestCosmeticEngine is a helper function to build a cosmetic engine for
// testing.  It adds rule storage close method to tb's cleanup.
func newTestCosmeticEngine(tb testing.TB) (eng *urlfilter.CosmeticEngine) {
	tb.Helper()

	rulesText := `##banner_generic
##banner_generic_disabled
example.org##banner_specific
example.org#@#banner_generic_disabled`

	lists := []filterlist.RuleList{
		&filterlist.StringRuleList{
			ID:             1,
			RulesText:      rulesText,
			IgnoreCosmetic: false,
		},
	}

	ruleStorage, err := filterlist.NewRuleStorage(lists)
	require.NoError(tb, err)

	testutil.CleanupAndRequireSuccess(tb, ruleStorage.Close)

	return urlfilter.NewCosmeticEngine(ruleStorage)
}
