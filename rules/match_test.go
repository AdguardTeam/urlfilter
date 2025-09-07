package rules_test

import (
	"testing"

	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMatchingResult(t *testing.T) {
	rs := testNewNetworkRules(t, []string{
		"||example.org^",
	}, 0)
	sourceRules := []*rules.NetworkRule{}
	result := rules.NewMatchingResult(rs, sourceRules)
	require.NotNil(t, result.BasicRule)
	require.NotNil(t, result.GetBasicResult())

	assert.Equal(t, "||example.org^", result.GetBasicResult().String())
}

func TestNewMatchingResultWhitelist(t *testing.T) {
	rs := testNewNetworkRules(t, []string{
		"||example.org^",
	}, 0)
	sourceRules := testNewNetworkRules(t, []string{
		"@@||example.com^$document",
	}, 0)
	result := rules.NewMatchingResult(rs, sourceRules)
	assert.Nil(t, result.BasicRule)
	assert.NotNil(t, result.DocumentRule)

	require.NotNil(t, result.GetBasicResult())

	assert.Equal(t, "@@||example.com^$document", result.GetBasicResult().String())
}

// TODO(a.garipov):  Rewrite into a table-driven test.
func TestGetCosmeticOption(t *testing.T) {
	// Simple case - no limitations
	rs := testNewNetworkRules(t, []string{
		"||example.org^",
	}, 0)
	sourceRules := []*rules.NetworkRule{}
	res := rules.NewMatchingResult(rs, sourceRules)
	assert.Equal(t, rules.CosmeticOptionAll, res.GetCosmeticOption())

	// $generichide
	rs = testNewNetworkRules(t, []string{
		"@@||example.org^$generichide",
	}, 0)
	sourceRules = []*rules.NetworkRule{}
	res = rules.NewMatchingResult(rs, sourceRules)
	assert.Equal(t, rules.CosmeticOptionCSS|rules.CosmeticOptionJS, res.GetCosmeticOption())

	// $jsinject
	rs = testNewNetworkRules(t, []string{
		"@@||example.org^$jsinject",
	}, 0)
	sourceRules = []*rules.NetworkRule{}
	res = rules.NewMatchingResult(rs, sourceRules)
	assert.Equal(t, rules.CosmeticOptionCSS|rules.CosmeticOptionGenericCSS, res.GetCosmeticOption())

	// $elemhide
	rs = testNewNetworkRules(t, []string{
		"@@||example.org^$elemhide",
	}, 0)
	sourceRules = []*rules.NetworkRule{}
	res = rules.NewMatchingResult(rs, sourceRules)
	assert.Equal(t, rules.CosmeticOptionJS, res.GetCosmeticOption())

	// $document
	rs = testNewNetworkRules(t, []string{
		"@@||example.org^$document",
	}, 0)
	sourceRules = []*rules.NetworkRule{}
	res = rules.NewMatchingResult(rs, sourceRules)
	assert.Equal(t, rules.CosmeticOptionNone, res.GetCosmeticOption())
}

func TestNewMatchingResultBadfilter(t *testing.T) {
	rs := testNewNetworkRules(t, []string{
		"||example.org^",
		"||example.org^$badfilter",
	}, 0)
	sourceRules := []*rules.NetworkRule{}
	result := rules.NewMatchingResult(rs, sourceRules)
	assert.Nil(t, result.BasicRule)
	assert.Nil(t, result.DocumentRule)
}

func TestNewMatchingResultBadfilterWhitelist(t *testing.T) {
	rs := testNewNetworkRules(t, []string{
		"||example.org^",
		"@@||example.org^",
		"@@||example.org^$badfilter",
	}, 0)
	sourceRules := []*rules.NetworkRule{}
	result := rules.NewMatchingResult(rs, sourceRules)
	assert.NotNil(t, result.BasicRule)
	assert.Nil(t, result.DocumentRule)

	require.NotNil(t, result.GetBasicResult())

	assert.Equal(t, "||example.org^", result.GetBasicResult().String())
}

func TestNewMatchingResultBadfilterSourceRules(t *testing.T) {
	rs := testNewNetworkRules(t, []string{
		"||example.org^",
	}, 0)
	sourceRules := testNewNetworkRules(t, []string{
		"@@||example.org^$document",
		"@@||example.org^$document,badfilter",
	}, 0)
	result := rules.NewMatchingResult(rs, sourceRules)

	assert.NotNil(t, result.BasicRule)
	assert.Nil(t, result.DocumentRule)

	require.NotNil(t, result.GetBasicResult())

	assert.Equal(t, "||example.org^", result.GetBasicResult().String())
}

// TODO(ameshkov):  Add more tests!

// testNewNetworkRules returns network rules created from lines.
func testNewNetworkRules(tb testing.TB, lines []string, id int) (rs []*rules.NetworkRule) {
	tb.Helper()

	for _, line := range lines {
		f, err := rules.NewNetworkRule(line, id)
		require.NoError(tb, err)

		rs = append(rs, f)
	}

	return rs
}

func TestGetDNSBasicRule(t *testing.T) {
	blockRule := newTestRule(t, "example.block")
	allowlistRule := newTestRule(t, "@@||example.allow^")
	importantBlockRule := newTestRule(t, "example.block$important")

	testCases := []struct {
		want *rules.NetworkRule
		name string
		rs   []*rules.NetworkRule
	}{{
		want: nil,
		rs:   []*rules.NetworkRule{},
		name: "empty",
	}, {
		want: blockRule,
		rs: []*rules.NetworkRule{
			blockRule,
		},
		name: "basic",
	}, {
		want: allowlistRule,
		rs: []*rules.NetworkRule{
			blockRule,
			allowlistRule,
		},
		name: "allowlist",
	}, {
		want: importantBlockRule,
		rs: []*rules.NetworkRule{
			blockRule,
			allowlistRule,
			importantBlockRule,
		},
		name: "important",
	}, {
		want: blockRule,
		rs: []*rules.NetworkRule{
			blockRule,
			newTestRule(t, "@@||example.org^$stealth"),
		},
		name: "stealth",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := rules.GetDNSBasicRule(tc.rs)
			assert.Equal(t, tc.want, r)
		})
	}
}

// newTestRule returns a network rule created from given source text.
func newTestRule(tb testing.TB, srcText string) (r *rules.NetworkRule) {
	tb.Helper()

	r, err := rules.NewNetworkRule(srcText, 1)
	require.NoError(tb, err)

	return r
}
