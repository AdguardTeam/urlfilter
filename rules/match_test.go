package rules_test

import (
	"testing"

	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMatchingResult(t *testing.T) {
	t.Parallel()

	rs := newTestNetworkRules(t, []string{"||example.org^"})
	sourceRules := []*rules.NetworkRule{}

	result := rules.NewMatchingResult(rs, sourceRules)
	require.NotNil(t, result.BasicRule)
	require.NotNil(t, result.GetBasicResult())

	assert.Equal(t, "||example.org^", result.GetBasicResult().String())
}

func TestNewMatchingResultWhitelist(t *testing.T) {
	t.Parallel()

	rs := newTestNetworkRules(t, []string{
		"||example.org^",
	})
	sourceRules := newTestNetworkRules(t, []string{
		"@@||example.com^$document",
	})

	result := rules.NewMatchingResult(rs, sourceRules)
	assert.Nil(t, result.BasicRule)
	assert.NotNil(t, result.DocumentRule)

	require.NotNil(t, result.GetBasicResult())

	assert.Equal(t, "@@||example.com^$document", result.GetBasicResult().String())
}

func TestMatchingResult_GetCosmeticOption(t *testing.T) {
	t.Parallel()

	sourceRules := []*rules.NetworkRule{}

	testCases := []struct {
		matchingResult *rules.MatchingResult
		name           string
		want           rules.CosmeticOption
	}{{
		matchingResult: rules.NewMatchingResult(
			newTestNetworkRules(t, []string{"||test.example^"}),
			sourceRules,
		),
		name: "no_limitations",
		want: rules.CosmeticOptionAll,
	}, {
		matchingResult: rules.NewMatchingResult(
			newTestNetworkRules(t, []string{"@@||test.example^$generichide"}),
			sourceRules,
		),
		name: "generichide",
		want: rules.CosmeticOptionCSS | rules.CosmeticOptionJS,
	}, {
		matchingResult: rules.NewMatchingResult(
			newTestNetworkRules(t, []string{"@@||test.example^$jsinject"}),
			sourceRules,
		),
		name: "jsinject",
		want: rules.CosmeticOptionCSS | rules.CosmeticOptionGenericCSS,
	}, {
		matchingResult: rules.NewMatchingResult(
			newTestNetworkRules(t, []string{"@@||test.example^$elemhide"}),
			sourceRules,
		),
		name: "elemhide",
		want: rules.CosmeticOptionJS,
	}, {
		matchingResult: rules.NewMatchingResult(
			newTestNetworkRules(t, []string{"@@||test.example^$document"}),
			sourceRules,
		),
		name: "document",
		want: rules.CosmeticOptionNone,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, tc.matchingResult.GetCosmeticOption())
		})
	}
}

func TestNewMatchingResult_badFilter(t *testing.T) {
	t.Parallel()

	rs := newTestNetworkRules(t, []string{
		"||example.org^",
		"||example.org^$badfilter",
	})
	sourceRules := []*rules.NetworkRule{}

	result := rules.NewMatchingResult(rs, sourceRules)
	assert.Nil(t, result.BasicRule)
	assert.Nil(t, result.DocumentRule)
}

func TestNewMatchingResult_badFilterWhitelist(t *testing.T) {
	t.Parallel()

	rs := newTestNetworkRules(t, []string{
		"||example.org^",
		"@@||example.org^",
		"@@||example.org^$badfilter",
	})
	sourceRules := []*rules.NetworkRule{}

	result := rules.NewMatchingResult(rs, sourceRules)
	assert.NotNil(t, result.BasicRule)
	assert.Nil(t, result.DocumentRule)

	require.NotNil(t, result.GetBasicResult())

	assert.Equal(t, "||example.org^", result.GetBasicResult().String())
}

func TestNewMatchingResult_badFilterSourceRules(t *testing.T) {
	t.Parallel()

	rs := newTestNetworkRules(t, []string{
		"||example.org^",
	})
	sourceRules := newTestNetworkRules(t, []string{
		"@@||example.org^$document",
		"@@||example.org^$document,badfilter",
	})
	result := rules.NewMatchingResult(rs, sourceRules)
	assert.NotNil(t, result.BasicRule)
	assert.Nil(t, result.DocumentRule)

	require.NotNil(t, result.GetBasicResult())

	assert.Equal(t, "||example.org^", result.GetBasicResult().String())
}

// TODO(ameshkov):  Add more tests!

func TestGetDNSBasicRule(t *testing.T) {
	blockRule := newTestNetworkRule(t, "example.block")
	allowlistRule := newTestNetworkRule(t, "@@||example.allow^")
	importantBlockRule := newTestNetworkRule(t, "example.block$important")

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
			newTestNetworkRule(t, "@@||example.org^$stealth"),
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

// newTestNetworkRules returns network rules created from the given lines.
func newTestNetworkRules(tb testing.TB, lines []string) (rs []*rules.NetworkRule) {
	tb.Helper()

	for _, line := range lines {
		rs = append(rs, newTestNetworkRule(tb, line))
	}

	return rs
}

// newTestNetworkRule returns a network rule created from given source text.
func newTestNetworkRule(tb testing.TB, srcText string) (r *rules.NetworkRule) {
	tb.Helper()

	r, err := rules.NewNetworkRule(srcText, testListID)
	require.NoError(tb, err)

	return r
}
