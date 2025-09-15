package rules_test

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkRule_options(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		option      rules.NetworkRuleOption
		wantEnabled bool
	}{{
		name:        "important",
		option:      rules.OptionImportant,
		wantEnabled: true,
	}, {
		name:        "third-party",
		option:      rules.OptionThirdParty,
		wantEnabled: true,
	}, {
		name:        "~first-party",
		option:      rules.OptionThirdParty,
		wantEnabled: true,
	}, {
		name:        "first-party",
		option:      rules.OptionThirdParty,
		wantEnabled: false,
	}, {
		name:        "~third-party",
		option:      rules.OptionThirdParty,
		wantEnabled: false,
	}, {
		name:        "match-case",
		option:      rules.OptionMatchCase,
		wantEnabled: true,
	}, {
		name:        "~match-case",
		option:      rules.OptionMatchCase,
		wantEnabled: false,
	}, {
		name:        "elemhide",
		option:      rules.OptionElemhide,
		wantEnabled: true,
	}, {
		name:        "generichide",
		option:      rules.OptionGenerichide,
		wantEnabled: true,
	}, {
		name:        "genericblock",
		option:      rules.OptionGenericblock,
		wantEnabled: true,
	}, {
		name:        "jsinject",
		option:      rules.OptionJsinject,
		wantEnabled: true,
	}, {
		name:        "urlblock",
		option:      rules.OptionUrlblock,
		wantEnabled: true,
	}, {
		name:        "content",
		option:      rules.OptionContent,
		wantEnabled: true,
	}, {
		name:        "extension",
		option:      rules.OptionExtension,
		wantEnabled: true,
	}, {
		name:        "document",
		option:      rules.OptionElemhide,
		wantEnabled: true,
	}, {
		name:        "document",
		option:      rules.OptionJsinject,
		wantEnabled: true,
	}, {
		name:        "document",
		option:      rules.OptionUrlblock,
		wantEnabled: true,
	}, {
		name:        "document",
		option:      rules.OptionContent,
		wantEnabled: true,
	}, {
		name:        "document",
		option:      rules.OptionExtension,
		wantEnabled: true,
	}, {
		name:        "stealth",
		option:      rules.OptionStealth,
		wantEnabled: true,
	}, {
		name:        "popup",
		option:      rules.OptionPopup,
		wantEnabled: true,
	}, {
		name:        "empty",
		option:      rules.OptionEmpty,
		wantEnabled: true,
	}, {
		name:        "mp4",
		option:      rules.OptionMp4,
		wantEnabled: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var ruleText string
			if (tc.option & rules.OptionWhitelistOnly) != 0 {
				ruleText = "@@"
			}
			ruleText += "||example.org$" + tc.name

			r, err := rules.NewNetworkRule(ruleText, testListID)
			require.NoError(t, err)
			require.NotNil(t, r)

			if tc.wantEnabled {
				assert.True(t, r.IsOptionEnabled(tc.option))
				assert.False(t, r.IsOptionDisabled(tc.option))
			} else {
				assert.True(t, r.IsOptionDisabled(tc.option))
				assert.False(t, r.IsOptionEnabled(tc.option))
			}
		})
	}
}

func TestNetworkRuleOption_Count(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		option rules.NetworkRuleOption
		want   int
	}{{
		option: rules.OptionImportant,
		want:   1,
	}, {
		option: rules.OptionImportant | rules.OptionStealth,
		want:   2,
	}, {
		option: rules.OptionImportant |
			rules.OptionStealth |
			rules.OptionRedirect |
			rules.OptionUrlblock,
		want: 4,
	}, {
		option: 0,
		want:   0,
	}}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("flags_%v", tc.want), func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.option.Count(), tc.want)
		})
	}
}

func TestNetworkRule_disabledOptions(t *testing.T) {
	t.Parallel()

	const ruleText = "@@||example.org$document,~extension"

	r, err := rules.NewNetworkRule(ruleText, testListID)
	require.NoError(t, err)
	require.NotNil(t, r)

	assert.False(t, r.IsOptionEnabled(rules.OptionExtension))
	assert.False(t, r.IsOptionDisabled(rules.OptionExtension))
}

func TestNetworkRule_Match_simpleBasicRules(t *testing.T) {
	t.Parallel()

	// Simple matching rule.
	r, err := rules.NewNetworkRule("||test.example^", testListID)
	req := rules.NewRequest(testURL, nil, rules.TypeOther)
	require.NoError(t, err)
	assert.True(t, r.Match(req))

	r, err = rules.NewNetworkRule("||test.example/*", testListID)
	req = rules.NewRequest(testURL, nil, rules.TypeOther)
	require.NoError(t, err)
	assert.True(t, r.Match(req))

	// Subdomains / domains.
	r, err = rules.NewNetworkRule("||github.com^", testListID)
	req = rules.NewRequestForHostname("dualstack.log.github.com-east-1.elb.amazonaws.com")
	require.NoError(t, err)
	assert.False(t, r.Match(req))

	req = rules.NewRequestForHostname("dualstack.log.github.com1-east-1.elb.amazonaws.com")
	require.NoError(t, err)
	assert.False(t, r.Match(req))

	// Simple regex rule.
	r, err = rules.NewNetworkRule("/test\\.example/", testListID)
	req = rules.NewRequest(testURL, nil, rules.TypeOther)
	require.NoError(t, err)
	assert.True(t, r.Match(req))

	// Simple pattern rule.
	r, err = rules.NewNetworkRule("_prebid_", testListID)
	req = rules.NewRequest(&url.URL{
		Scheme:   urlutil.SchemeHTTPS,
		Host:     "ap.lijit.com",
		Path:     "/rtb/bid",
		RawQuery: "src=prebid_prebid_1.35.0",
	}, &url.URL{
		Scheme: urlutil.SchemeHTTPS,
		Host:   "www.drudgereport.com",
	}, rules.TypeXmlhttprequest)
	require.NoError(t, err)
	assert.True(t, r.Match(req))
}

func TestNetworkRule_invalidModifiers(t *testing.T) {
	t.Parallel()

	r, err := rules.NewNetworkRule("||example.org^$unknown", testListID)
	assert.Error(t, err)
	assert.Nil(t, r)

	// Whitelist-only modifier.
	r, err = rules.NewNetworkRule("||example.org^$elemhide", testListID)
	assert.Error(t, err)
	assert.Nil(t, r)

	// Blacklist-only modifier.
	r, err = rules.NewNetworkRule("@@||example.org^$popup", testListID)
	assert.Error(t, err)
	assert.Nil(t, r)
}

func TestNetworkRule_Match_case(t *testing.T) {
	t.Parallel()

	r, err := rules.NewNetworkRule("||test.example^$match-case", testListID)
	req := rules.NewRequest(testURL, nil, rules.TypeOther)
	require.NoError(t, err)
	assert.True(t, r.Match(req))

	req = rules.NewRequest(&url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   strings.ToUpper(testHostname),
	}, nil, rules.TypeOther)
	require.NoError(t, err)
	assert.False(t, r.Match(req))
}

func TestNetworkRule_Match_thirdParty(t *testing.T) {
	t.Parallel()

	r, err := rules.NewNetworkRule("||test.example^$third-party", testListID)

	// First-party 1.
	req := rules.NewRequest(testURL, nil, rules.TypeOther)
	require.NoError(t, err)
	assert.False(t, r.Match(req))

	// First-party 2.
	req = rules.NewRequest(testURLSub, testURL, rules.TypeOther)
	require.NoError(t, err)
	assert.False(t, r.Match(req))

	// Third-party.
	req = rules.NewRequest(testURL, testURLOther, rules.TypeOther)
	require.NoError(t, err)
	assert.True(t, r.Match(req))

	r, err = rules.NewNetworkRule("||test.example^$first-party", testListID)

	// First-party 1.
	req = rules.NewRequest(testURL, nil, rules.TypeOther)
	require.NoError(t, err)
	assert.True(t, r.Match(req))

	// First-party.
	req = rules.NewRequest(testURLSub, testURL, rules.TypeOther)
	require.NoError(t, err)
	assert.True(t, r.Match(req))

	// Third-party.
	req = rules.NewRequest(testURL, testURLOther, rules.TypeOther)
	require.NoError(t, err)
	assert.False(t, r.Match(req))
}

func TestNetworkRule_Match_contentType(t *testing.T) {
	t.Parallel()

	// $script.
	r, err := rules.NewNetworkRule("||test.example^$script", testListID)
	req := rules.NewRequest(testURL, nil, rules.TypeScript)
	require.NoError(t, err)
	assert.True(t, r.Match(req))

	req = rules.NewRequest(testURL, nil, rules.TypeDocument)
	require.NoError(t, err)
	assert.False(t, r.Match(req))

	// $script and $stylesheet.
	r, err = rules.NewNetworkRule("||test.example^$script,stylesheet", testListID)
	req = rules.NewRequest(testURL, nil, rules.TypeScript)
	require.NoError(t, err)
	assert.True(t, r.Match(req))

	req = rules.NewRequest(testURL, nil, rules.TypeStylesheet)
	require.NoError(t, err)
	assert.True(t, r.Match(req))

	req = rules.NewRequest(testURL, nil, rules.TypeDocument)
	require.NoError(t, err)
	assert.False(t, r.Match(req))

	// Everything except $script and $stylesheet.
	r, err = rules.NewNetworkRule("@@||test.example^$~script,~stylesheet", testListID)
	req = rules.NewRequest(testURL, nil, rules.TypeScript)
	require.NoError(t, err)
	assert.False(t, r.Match(req))

	req = rules.NewRequest(testURL, nil, rules.TypeStylesheet)
	require.NoError(t, err)
	assert.False(t, r.Match(req))

	req = rules.NewRequest(testURL, nil, rules.TypeDocument)
	require.NoError(t, err)
	assert.True(t, r.Match(req))
}

func TestNetworkRule_Match_domainRestrictions(t *testing.T) {
	t.Parallel()

	// Just one permitted domain.
	r, err := rules.NewNetworkRule("||test.example^$domain=test.example", testListID)
	req := rules.NewRequest(testURL, nil, rules.TypeScript)
	require.NoError(t, err)
	assert.False(t, r.Match(req))

	req = rules.NewRequest(testURL, testURL, rules.TypeScript)
	require.NoError(t, err)
	assert.True(t, r.Match(req))

	req = rules.NewRequest(testURL, testURLSub, rules.TypeScript)
	require.NoError(t, err)
	assert.True(t, r.Match(req))

	// One permitted, subdomain restricted.
	r, err = rules.NewNetworkRule(
		"||test.example^$domain=test.example|~sub.test.example",
		testListID,
	)
	req = rules.NewRequest(testURL, nil, rules.TypeScript)
	require.NoError(t, err)
	assert.False(t, r.Match(req))

	req = rules.NewRequest(testURL, testURL, rules.TypeScript)
	require.NoError(t, err)
	assert.True(t, r.Match(req))

	req = rules.NewRequest(testURL, testURLSub, rules.TypeScript)
	require.NoError(t, err)
	assert.False(t, r.Match(req))

	// One restricted.
	r, err = rules.NewNetworkRule("||test.example^$domain=~test.example", testListID)
	req = rules.NewRequest(testURL, nil, rules.TypeScript)
	require.NoError(t, err)
	assert.True(t, r.Match(req))

	req = rules.NewRequest(testURL, testURL, rules.TypeScript)
	require.NoError(t, err)
	assert.False(t, r.Match(req))

	req = rules.NewRequest(testURL, testURLSub, rules.TypeScript)
	require.NoError(t, err)
	assert.False(t, r.Match(req))

	// Wide restricted.
	r, err = rules.NewNetworkRule("$domain=test.example", testListID)
	req = rules.NewRequest(testURLOther, testURL, rules.TypeScript)
	require.NoError(t, err)
	assert.True(t, r.Match(req))
}

func TestNetworkRule_Match_denyallow(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		want               assert.BoolAssertionFunc
		requestURL         *url.URL
		sourceURL          *url.URL
		testName           string
		ruleText           string
		wantErrMsg         string
		requestForHostname bool
	}{{
		want:               assert.False,
		requestURL:         nil,
		sourceURL:          nil,
		testName:           "denyallow_invalid_inversion",
		ruleText:           "*^$denyallow=~test.example",
		wantErrMsg:         `invalid $denyallow value: "~test.example"`,
		requestForHostname: false,
	}, {
		want:               assert.False,
		requestURL:         nil,
		sourceURL:          nil,
		testName:           "denyallow_invalid_empty",
		ruleText:           "*^$denyallow",
		wantErrMsg:         "no domains specified",
		requestForHostname: false,
	}, {
		want:               assert.False,
		requestURL:         testURL,
		sourceURL:          nil,
		testName:           "denyallow_unblock_tld",
		ruleText:           "*^$denyallow=example",
		wantErrMsg:         "",
		requestForHostname: false,
	}, {
		want:               assert.False,
		requestURL:         testURL,
		sourceURL:          nil,
		testName:           "denyallow_found",
		ruleText:           "*^$denyallow=test.example",
		wantErrMsg:         "",
		requestForHostname: false,
	}, {
		want:               assert.False,
		requestURL:         testURLSub,
		sourceURL:          nil,
		testName:           "denyallow_found_subdomain",
		ruleText:           "*^$denyallow=test.example",
		wantErrMsg:         "",
		requestForHostname: false,
	}, {
		want:               assert.True,
		requestURL:         testURLOther,
		sourceURL:          nil,
		testName:           "denyallow_not_found",
		ruleText:           "*^$denyallow=test.example",
		wantErrMsg:         "",
		requestForHostname: false,
	}, {
		want:               assert.False,
		requestURL:         testURL,
		sourceURL:          nil,
		testName:           "denyallow_found_multiple_domains",
		ruleText:           "*^$denyallow=test.example|example.net",
		wantErrMsg:         "",
		requestForHostname: false,
	}, {
		want:               assert.True,
		requestURL:         testURLOther,
		sourceURL:          testURL,
		testName:           "denyallow_and_domain_blocking",
		ruleText:           "*^$domain=test.example,denyallow=essentialdomain.net",
		wantErrMsg:         "",
		requestForHostname: false,
	}, {
		want: assert.False,
		requestURL: &url.URL{
			Scheme: urlutil.SchemeHTTPS,
			Host:   "essentialdomain.net",
		},
		sourceURL:          testURL,
		testName:           "denyallow_and_domain_not_blocking",
		ruleText:           "*^$domain=test.example,denyallow=essentialdomain.net",
		wantErrMsg:         "",
		requestForHostname: false,
	}, {
		want: assert.False,
		requestURL: &url.URL{
			Scheme: urlutil.SchemeHTTPS,
			Host:   "192.168.1.1",
		},
		sourceURL:          nil,
		testName:           "denyallow_does_not_match_ips",
		ruleText:           "*$denyallow=com",
		wantErrMsg:         "",
		requestForHostname: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			t.Parallel()

			r, err := rules.NewNetworkRule(tc.ruleText, testListID)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			if tc.wantErrMsg != "" {
				return
			}

			req := rules.NewRequest(tc.requestURL, tc.sourceURL, rules.TypeScript)
			req.IsHostnameRequest = tc.requestForHostname

			tc.want(t, r.Match(req))
		})
	}
}

func TestNetworkRule_Match_wildcardTLDRestrictions(t *testing.T) {
	t.Parallel()

	r, err := rules.NewNetworkRule("||example.org^$domain=example.*", testListID)
	require.NoError(t, err)

	testCases := []struct {
		want      assert.BoolAssertionFunc
		sourceURL *url.URL
		name      string
	}{{
		want:      assert.False,
		sourceURL: nil,
		name:      "nil",
	}, {
		want: assert.True,
		sourceURL: &url.URL{
			Scheme: urlutil.SchemeHTTPS,
			Host:   "example.com",
		},
		name: "match",
	}, {
		want: assert.True,
		sourceURL: &url.URL{
			Scheme: urlutil.SchemeHTTPS,
			Host:   "example.co.uk",
		},
		name: "match_long_suffix",
	}, {
		want: assert.True,
		sourceURL: &url.URL{
			Scheme: urlutil.SchemeHTTPS,
			Host:   "test.example.co.uk",
		},
		name: "match_sub_long_suffix",
	}, {
		want: assert.False,
		sourceURL: &url.URL{
			Scheme: urlutil.SchemeHTTPS,
			Host:   "example.local",
		},
		name: "match_not_public_suffix",
	}, {
		want: assert.False,
		sourceURL: &url.URL{
			Scheme: urlutil.SchemeHTTPS,
			Host:   "example.test.test",
		},
		name: "sub_public_suffix",
	}}

	requestURL := &url.URL{
		Scheme: urlutil.SchemeHTTPS,
		Host:   "example.org",
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := rules.NewRequest(requestURL, tc.sourceURL, rules.TypeScript)
			tc.want(t, r.Match(req))
		})
	}
}

func TestNetworkRule_invalidDomainRestrictions(t *testing.T) {
	t.Parallel()

	_, err := rules.NewNetworkRule("||example.org^$domain=", testListID)
	assert.Error(t, err)

	_, err = rules.NewNetworkRule("||example.org^$domain=|example.com", testListID)
	assert.Error(t, err)
}

func TestNetworkRule_Match_client(t *testing.T) {
	t.Parallel()

	r, err := rules.NewNetworkRule("||test.example^$client=127.0.0.1", testListID)
	require.NoError(t, err)
	assert.NotNil(t, r)

	req := rules.NewRequestForHostname(testHostname)
	req.ClientIP = netip.MustParseAddr("127.0.0.1")
	assert.True(t, r.Match(req))

	req.ClientIP = netip.MustParseAddr("127.0.0.2")
	assert.False(t, r.Match(req))

	r, err = rules.NewNetworkRule("||test.example^$client=127.0.0.0/8", testListID)
	require.NoError(t, err)
	assert.NotNil(t, r)

	req.ClientIP = netip.MustParseAddr("127.1.1.1")
	assert.True(t, r.Match(req))

	req.ClientIP = netip.MustParseAddr("126.0.0.0")
	assert.False(t, r.Match(req))

	r, err = rules.NewNetworkRule("||test.example^$client=2001::0:00c0:ffee", testListID)
	require.NoError(t, err)
	assert.NotNil(t, r)

	req.ClientIP = netip.MustParseAddr("2001::c0:ffee")
	assert.True(t, r.Match(req))

	req.ClientIP = netip.MustParseAddr("2001::c0:ffef")
	assert.False(t, r.Match(req))

	r, err = rules.NewNetworkRule("||test.example^$client=2001::0:00c0:ffee/112", testListID)
	require.NoError(t, err)
	assert.NotNil(t, r)

	req.ClientIP = netip.MustParseAddr("2001::0:c0:0")
	assert.True(t, r.Match(req))

	req.ClientIP = netip.MustParseAddr("2001::c1:ffee")
	assert.False(t, r.Match(req))

	r, err = rules.NewNetworkRule("||test.example^$client=~'Frank\\'s laptop'", testListID)
	require.NoError(t, err)
	assert.NotNil(t, r)

	req.ClientName = "Frank's laptop"
	assert.False(t, r.Match(req))

	req.ClientName = "Frank's phone"
	assert.True(t, r.Match(req))

	r, err = rules.NewNetworkRule("||test.example^$client=name", testListID)
	require.NoError(t, err)
	assert.NotNil(t, r)

	req.ClientIP = netip.MustParseAddr("127.0.0.1")
	req.ClientName = "name"
	assert.True(t, r.Match(req))

	req.ClientIP = netip.MustParseAddr("127.0.0.1")
	req.ClientName = "another-name"
	assert.False(t, r.Match(req))
}

func TestNetworkRule_IsHigherPriority(t *testing.T) {
	t.Parallel()

	// whitelist+$important --> every other
	compareRulesPriority(t, "@@||example.org$important", "@@||example.org$important", false)
	compareRulesPriority(t, "@@||example.org$important", "||example.org$important", true)
	compareRulesPriority(t, "@@||example.org$important", "@@||example.org", true)
	compareRulesPriority(t, "@@||example.org$important", "||example.org", true)

	// $important -> whitelist
	compareRulesPriority(t, "||example.org$important", "@@||example.org$important", false)
	compareRulesPriority(t, "||example.org$important", "||example.org$important", false)
	compareRulesPriority(t, "||example.org$important", "@@||example.org", true)
	compareRulesPriority(t, "||example.org$important", "||example.org", true)

	// whitelist -> basic
	compareRulesPriority(t, "@@||example.org", "@@||example.org$important", false)
	compareRulesPriority(t, "@@||example.org", "||example.org$important", false)
	compareRulesPriority(t, "@@||example.org", "@@||example.org", false)
	compareRulesPriority(t, "@@||example.org", "||example.org", true)

	compareRulesPriority(t, "||example.org", "@@||example.org$important", false)
	compareRulesPriority(t, "||example.org", "||example.org$important", false)
	compareRulesPriority(t, "||example.org", "@@||example.org", false)
	compareRulesPriority(t, "||example.org", "||example.org", false)

	// specific -> generic
	compareRulesPriority(t, "||example.org$domain=example.org", "||example.org$script,stylesheet", true)

	// more modifiers -> less modifiers
	compareRulesPriority(t, "||example.org$script,stylesheet", "||example.org$script", true)
	compareRulesPriority(t, "||example.org$ctag=123,client=123", "||example.org$script", true)
	compareRulesPriority(t, "||example.org$ctag=123,client=123,dnstype=AAAA", "||example.org$client=123,dnstype=AAAA", true)
	compareRulesPriority(t, "||example.org$denyallow=com", "||example.org", true)
}

func TestNetworkRule_Match_source(t *testing.T) {
	t.Parallel()

	u, err := url.Parse("https://ci.phncdn.com/videos/201809/25/184777011/original/(m=ecuKGgaaaa)(mh=VSmV9NL_iouBcWJJ)4.jpg")
	require.NoError(t, err)

	sourceURL, err := url.Parse("https://www.pornhub.com/view_video.php?viewkey=ph5be89d11de4b0")
	require.NoError(t, err)

	req := rules.NewRequest(u, sourceURL, rules.TypeImage)
	ruleText := "|https://$image,media,script,third-party,domain=" +
		"~feedback.pornhub.com|pornhub.com|redtube.com|redtube.com.br|tube8.com|" +
		"tube8.es|tube8.fr|youporn.com|youporngay.com"

	r, err := rules.NewNetworkRule(ruleText, testListID)
	require.NoError(t, err)

	assert.True(t, r.Match(req))
}

func TestNetworkRule_invalidRule(t *testing.T) {
	t.Parallel()

	r, err := rules.NewNetworkRule("*$third-party", testListID)
	assert.Nil(t, r)
	assert.ErrorIs(t, err, rules.ErrTooWideRule)

	r, err = rules.NewNetworkRule("$third-party", testListID)
	assert.Nil(t, r)
	assert.ErrorIs(t, err, rules.ErrTooWideRule)

	r, err = rules.NewNetworkRule("ad$third-party", testListID)
	assert.Nil(t, r)
	assert.ErrorIs(t, err, rules.ErrTooWideRule)

	// This one is valid because it has domain restriction.
	r, err = rules.NewNetworkRule("$domain=ya.ru", testListID)
	require.NoError(t, err)
	assert.NotNil(t, r)

	// This one is valid because it has $ctag restriction.
	r, err = rules.NewNetworkRule("$ctag=pc", testListID)
	require.NoError(t, err)
	assert.NotNil(t, r)

	// This one is valid because it has $client restriction.
	r, err = rules.NewNetworkRule("$client=127.0.0.1", testListID)
	require.NoError(t, err)
	assert.NotNil(t, r)

	// This one is valid because it has $client restriction.
	r, err = rules.NewNetworkRule("/$client=127.0.0.1", testListID)
	require.NoError(t, err)
	require.NotNil(t, r)

	req := rules.NewRequest(testURL, nil, rules.TypeOther)
	req.ClientIP = netip.MustParseAddr("127.0.0.1")
	assert.True(t, r.Match(req))
}

func TestNetworkRule_IsHostLevelNetworkRule(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		want     assert.BoolAssertionFunc
		name     string
		ruleText string
	}{{
		want:     assert.True,
		name:     "important",
		ruleText: "||example.org^$important",
	}, {
		want:     assert.True,
		name:     "important_badfilter",
		ruleText: "||example.org^$important,badfilter",
	}, {
		want:     assert.True,
		name:     "badfilter",
		ruleText: "||example.org^$badfilter",
	}, {
		want:     assert.True,
		name:     "no_options",
		ruleText: "||example.org",
	}, {
		want:     assert.False,
		name:     "no_thirdparty",
		ruleText: "||example.org^$~third-party",
	}, {
		want:     assert.False,
		name:     "thirdparty",
		ruleText: "||example.org^$third-party",
	}, {
		want:     assert.False,
		name:     "domain",
		ruleText: "||example.org^$domain=example.com",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, err := rules.NewNetworkRule(tc.ruleText, testListID)
			require.NoError(t, err)

			tc.want(t, r.IsHostLevelNetworkRule())
		})
	}
}

func TestNetworkRule_Match_ip(t *testing.T) {
	t.Parallel()

	r, err := rules.NewNetworkRule("://104.154.", testListID)
	require.NoError(t, err)
	require.True(t, r.IsHostLevelNetworkRule())

	req := rules.NewRequestForHostname("104.154.1.1")
	assert.True(t, r.Match(req))

	req = rules.NewRequestForHostname("1.104.154.1")
	assert.False(t, r.Match(req))
}

func TestNetworkRule_Match_subdomain(t *testing.T) {
	t.Parallel()

	r, err := rules.NewNetworkRule("/sub.", testListID)
	require.NoError(t, err)

	req := rules.NewRequestForHostname("sub.example.org")
	assert.True(t, r.Match(req))

	req = rules.NewRequestForHostname("sub.host.org")
	assert.True(t, r.Match(req))

	req = rules.NewRequestForHostname("sub2.host.org")
	assert.False(t, r.Match(req))

	req = rules.NewRequestForHostname("2sub.host.org")
	assert.False(t, r.Match(req))
}

// compareRulesPriority is a helper function to compare the priority of the two
// given rules.
func compareRulesPriority(tb testing.TB, left, right string, expected bool) {
	tb.Helper()

	l, err := rules.NewNetworkRule(left, testListID)
	require.NoError(tb, err)

	r, err := rules.NewNetworkRule(right, testListID)
	require.NoError(tb, err)

	assert.Equal(tb, expected, l.IsHigherPriority(r))
}

func TestNetworkRule_Match_dnsType(t *testing.T) {
	t.Parallel()

	req := rules.NewRequestForHostname(testHostname)
	req.DNSType = dns.TypeAAAA

	r, err := rules.NewNetworkRule("||test.example^$dnstype=TXT|AAAA", testListID)
	require.NoError(t, err)
	assert.True(t, r.Match(req))

	r, err = rules.NewNetworkRule("||test.example^$dnstype=~TXT|~AAAA", testListID)
	require.NoError(t, err)
	assert.False(t, r.Match(req))

	r, err = rules.NewNetworkRule("$dnstype=AAAA", testListID)
	require.NoError(t, err)
	assert.True(t, r.Match(req))

	t.Run("parse_errors", func(t *testing.T) {
		_, err = rules.NewNetworkRule("||test.example^$dnstype=", testListID)
		assert.Error(t, err)

		_, err = rules.NewNetworkRule("||test.example^$dnstype=TXT|", testListID)
		assert.Error(t, err)

		_, err = rules.NewNetworkRule("||test.example^$dnstype=NONE", testListID)
		assert.Error(t, err)

		_, err = rules.NewNetworkRule("||test.example^$dnstype=INVALIDTYPE", testListID)
		assert.Error(t, err)
	})
}

func BenchmarkNetworkRule_Match(b *testing.B) {
	r, err := rules.NewNetworkRule("||test.example^", testListID)
	require.NoError(b, err)

	req := rules.NewRequestForHostname(testHostname)

	// Warmup to make sure the init has run.
	ok := r.Match(req)
	require.True(b, ok)

	b.ReportAllocs()
	for b.Loop() {
		ok = r.Match(req)
	}

	require.True(b, ok)

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter/rules
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkNetworkRule_Match-16    	 1793748	       670.3 ns/op	       0 B/op	       0 allocs/op
}

func FuzzNetworkRule_Match(f *testing.F) {
	r, err := rules.NewNetworkRule("||test.example^", testListID)
	require.NoError(f, err)

	for _, seed := range []string{
		"",
		" ",
		"\n",
		"1",
		"127.0.0.1",
		"test.example",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, domain string) {
		req := rules.NewRequestForHostname(domain)

		assert.NotPanics(t, func() {
			_ = r.Match(req)
		})
	})
}
