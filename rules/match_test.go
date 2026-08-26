package rules_test

import (
	"testing"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/urlfilter/internal/uftest"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test rules sources.
const (
	ruleSrcWhitelist = "@@" + uftest.RuleHost
)

// Test rules.
var (
	blockingRule          = mustNewTestRule(uftest.RuleHost)
	whitelistRule         = mustNewTestRule(ruleSrcWhitelist)
	whitelistDocumentRule = mustNewTestRule(ruleSrcWhitelist + "$document")

	badFltRule                  = mustNewTestRule(uftest.RuleHost + "$badfilter")
	badFltWhitelistRule         = mustNewTestRule(ruleSrcWhitelist + "$badfilter")
	badFltWhitelistDocumentRule = mustNewTestRule(ruleSrcWhitelist + "$document,badfilter")
)

// matchingResultTestCases is a list of test cases for NewMatchingResult.
var matchingResultTestCases = []struct {
	wantBasicResult  *rules.NetworkRule
	wantBasicRule    *rules.NetworkRule
	wantDocumentRule *rules.NetworkRule
	name             string
	rules            []*rules.NetworkRule
	sourceRules      []*rules.NetworkRule
}{{
	wantBasicResult:  blockingRule,
	wantBasicRule:    blockingRule,
	wantDocumentRule: nil,
	name:             "basic",
	rules: []*rules.NetworkRule{
		blockingRule,
	},
	sourceRules: []*rules.NetworkRule{},
}, {
	wantBasicResult:  whitelistRule,
	wantBasicRule:    whitelistRule,
	wantDocumentRule: nil,
	name:             "whitelist",
	rules: []*rules.NetworkRule{
		blockingRule,
		whitelistRule,
	},
	sourceRules: []*rules.NetworkRule{},
}, {
	wantBasicResult:  whitelistDocumentRule,
	wantBasicRule:    nil,
	wantDocumentRule: whitelistDocumentRule,
	name:             "source_whitelist",
	rules: []*rules.NetworkRule{
		blockingRule,
	},
	sourceRules: []*rules.NetworkRule{
		whitelistDocumentRule,
	},
}, {
	wantBasicResult:  nil,
	wantBasicRule:    nil,
	wantDocumentRule: nil,
	name:             "badfilter",
	rules: []*rules.NetworkRule{
		blockingRule,
		badFltRule,
	},
	sourceRules: []*rules.NetworkRule{},
}, {
	wantBasicResult:  blockingRule,
	wantBasicRule:    blockingRule,
	wantDocumentRule: nil,
	name:             "badfilter_whitelist",
	rules: []*rules.NetworkRule{
		blockingRule,
		whitelistRule,
		badFltWhitelistRule,
	},
	sourceRules: []*rules.NetworkRule{},
}, {
	wantBasicResult:  blockingRule,
	wantBasicRule:    blockingRule,
	wantDocumentRule: nil,
	name:             "badfilter_source_whitelist",
	rules: []*rules.NetworkRule{
		blockingRule,
	},
	sourceRules: []*rules.NetworkRule{
		whitelistDocumentRule,
		badFltWhitelistDocumentRule,
	},
}}

func TestNewMatchingResult(t *testing.T) {
	t.Parallel()

	for _, tc := range matchingResultTestCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result := rules.NewMatchingResult(tc.rules, tc.sourceRules)
			require.NotNil(t, result)

			assert.Equal(t, tc.wantBasicRule, result.BasicRule)
			assert.Equal(t, tc.wantDocumentRule, result.DocumentRule)
			assert.Equal(t, tc.wantBasicResult, result.GetBasicResult())
		})
	}
}

func BenchmarkNewMatchingResult(b *testing.B) {
	for _, tc := range matchingResultTestCases {
		b.Run(tc.name, func(b *testing.B) {
			var result *rules.MatchingResult

			b.ReportAllocs()
			for b.Loop() {
				result = rules.NewMatchingResult(tc.rules, tc.sourceRules)
			}

			require.NotNil(b, result)
		})
	}

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/urlfilter/rules
	//	cpu: Apple M1 Pro
	//	BenchmarkNewMatchingResult/basic-8         	24137907	        42.62 ns/op	      96 B/op	       1 allocs/op
	//	BenchmarkNewMatchingResult/whitelist-8     	21755403	        53.91 ns/op	      96 B/op	       1 allocs/op
	//	BenchmarkNewMatchingResult/source_whitelist-8         	27316132	        43.73 ns/op	      96 B/op	       1 allocs/op
	//	BenchmarkNewMatchingResult/badfilter-8                	18695810	        63.11 ns/op	      96 B/op	       1 allocs/op
	//	BenchmarkNewMatchingResult/badfilter_whitelist-8      	12009487	        94.78 ns/op	     104 B/op	       2 allocs/op
	//	BenchmarkNewMatchingResult/badfilter_source_whitelist-8         	17999988	        65.96 ns/op	      96 B/op	       1 allocs/op
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

// TODO(ameshkov):  Add more tests!

func TestGetDNSBasicRule(t *testing.T) {
	t.Parallel()

	blockRule := uftest.NewNetworkRule(t, "example.block")
	allowlistRule := uftest.NewNetworkRule(t, "@@||example.allow^")
	importantBlockRule := uftest.NewNetworkRule(t, "example.block$important")

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
			uftest.NewNetworkRule(t, "@@||example.org^$stealth"),
		},
		name: "stealth",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := rules.GetDNSBasicRule(tc.rs)
			assert.Equal(t, tc.want, r)
		})
	}
}

func TestGetDNSBasicRule_badfilterCollisions(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		lines []string
	}{
		{
			name: "colliding_rules",
			lines: []string{
				"||github.io^",
				"||*.io^",
				"||github.io^$badfilter",
				"||*.io^$badfilter",
			},
		},
		{
			name: "unrelated_badfilter",
			lines: []string{
				"||blogspot.com^",
				"||blogspot.com^$badfilter",
				"||*.com^$badfilter",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Nil(t, rules.GetDNSBasicRule(newTestNetworkRules(t, tc.lines)))
		})
	}
}

// newTestNetworkRules returns network rules created from the given lines.
func newTestNetworkRules(tb testing.TB, lines []string) (rs []*rules.NetworkRule) {
	tb.Helper()

	for _, line := range lines {
		rs = append(rs, uftest.NewNetworkRule(tb, line))
	}

	return rs
}

// mustNewTestRule returns a network rule created from given source text.
func mustNewTestRule(srcText string) (r *rules.NetworkRule) {
	return errors.Must(rules.NewNetworkRule(srcText, uftest.ListID1))
}
