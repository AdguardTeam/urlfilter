package rules_test

import (
	"fmt"
	"net/netip"
	"net/url"
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

			f, err := rules.NewNetworkRule(ruleText, 0)
			require.NoError(t, err)
			require.NotNil(t, f)

			if tc.wantEnabled {
				assert.True(t, f.IsOptionEnabled(tc.option))
				assert.False(t, f.IsOptionDisabled(tc.option))
			} else {
				assert.True(t, f.IsOptionDisabled(tc.option))
				assert.False(t, f.IsOptionEnabled(tc.option))
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

	f, err := rules.NewNetworkRule(ruleText, 0)
	require.NoError(t, err)
	require.NotNil(t, f)

	assert.False(t, f.IsOptionEnabled(rules.OptionExtension))
	assert.False(t, f.IsOptionDisabled(rules.OptionExtension))
}

func TestNetworkRule_Match_simpleBasicRules(t *testing.T) {
	t.Parallel()

	// Simple matching rule.
	f, err := rules.NewNetworkRule("||test.example^", 0)
	r := rules.NewRequest(testURLStr, "", rules.TypeOther)
	require.NoError(t, err)
	assert.True(t, f.Match(r))

	f, err = rules.NewNetworkRule("||test.example/*", 0)
	r = rules.NewRequest(testURLStr, "", rules.TypeOther)
	require.NoError(t, err)
	assert.True(t, f.Match(r))

	// Subdomains / domains.
	f, err = rules.NewNetworkRule("||github.com^", 0)
	r = rules.NewRequestForHostname("dualstack.log.github.com-east-1.elb.amazonaws.com")
	require.NoError(t, err)
	assert.False(t, f.Match(r))

	r = rules.NewRequestForHostname("dualstack.log.github.com1-east-1.elb.amazonaws.com")
	require.NoError(t, err)
	assert.False(t, f.Match(r))

	// Simple regex rule.
	f, err = rules.NewNetworkRule("/test\\.example/", 0)
	r = rules.NewRequest(testURLStr, "", rules.TypeOther)
	require.NoError(t, err)
	assert.True(t, f.Match(r))

	// Simple pattern rule.
	f, err = rules.NewNetworkRule("_prebid_", 0)
	r = rules.NewRequest(
		"https://ap.lijit.com/rtb/bid?src=prebid_prebid_1.35.0",
		"https://www.drudgereport.com/",
		rules.TypeXmlhttprequest,
	)
	require.NoError(t, err)
	assert.True(t, f.Match(r))
}

func TestNetworkRule_invalidModifiers(t *testing.T) {
	t.Parallel()

	f, err := rules.NewNetworkRule("||example.org^$unknown", 0)
	assert.Error(t, err)
	assert.Nil(t, f)

	// Whitelist-only modifier.
	f, err = rules.NewNetworkRule("||example.org^$elemhide", 0)
	assert.Error(t, err)
	assert.Nil(t, f)

	// Blacklist-only modifier.
	f, err = rules.NewNetworkRule("@@||example.org^$popup", 0)
	assert.Error(t, err)
	assert.Nil(t, f)
}

func TestNetworkRule_Match_case(t *testing.T) {
	t.Parallel()

	f, err := rules.NewNetworkRule("||test.example^$match-case", 0)
	r := rules.NewRequest(testURLStr, "", rules.TypeOther)
	require.NoError(t, err)
	assert.True(t, f.Match(r))

	r = rules.NewRequest("https://EXAMPLE.org/", "", rules.TypeOther)
	require.NoError(t, err)
	assert.False(t, f.Match(r))
}

func TestNetworkRule_Match_thirdParty(t *testing.T) {
	t.Parallel()

	f, err := rules.NewNetworkRule("||test.example^$third-party", 0)

	// First-party 1.
	r := rules.NewRequest(testURLStr, "", rules.TypeOther)
	require.NoError(t, err)
	assert.False(t, f.Match(r))

	// First-party 2.
	r = rules.NewRequest(testURLSubStr, testURLStr, rules.TypeOther)
	require.NoError(t, err)
	assert.False(t, f.Match(r))

	// Third-party.
	r = rules.NewRequest(testURLStr, testURLOtherStr, rules.TypeOther)
	require.NoError(t, err)
	assert.True(t, f.Match(r))

	f, err = rules.NewNetworkRule("||test.example^$first-party", 0)

	// First-party 1.
	r = rules.NewRequest(testURLStr, "", rules.TypeOther)
	require.NoError(t, err)
	assert.True(t, f.Match(r))

	// First-party.
	r = rules.NewRequest(testURLSubStr, testURLStr, rules.TypeOther)
	require.NoError(t, err)
	assert.True(t, f.Match(r))

	// Third-party.
	r = rules.NewRequest(testURLStr, testURLOtherStr, rules.TypeOther)
	require.NoError(t, err)
	assert.False(t, f.Match(r))
}

func TestNetworkRule_Match_contentType(t *testing.T) {
	t.Parallel()

	// $script.
	f, err := rules.NewNetworkRule("||test.example^$script", 0)
	r := rules.NewRequest(testURLStr, "", rules.TypeScript)
	require.NoError(t, err)
	assert.True(t, f.Match(r))

	r = rules.NewRequest(testURLStr, "", rules.TypeDocument)
	require.NoError(t, err)
	assert.False(t, f.Match(r))

	// $script and $stylesheet.
	f, err = rules.NewNetworkRule("||test.example^$script,stylesheet", 0)
	r = rules.NewRequest(testURLStr, "", rules.TypeScript)
	require.NoError(t, err)
	assert.True(t, f.Match(r))

	r = rules.NewRequest(testURLStr, "", rules.TypeStylesheet)
	require.NoError(t, err)
	assert.True(t, f.Match(r))

	r = rules.NewRequest(testURLStr, "", rules.TypeDocument)
	require.NoError(t, err)
	assert.False(t, f.Match(r))

	// Everything except $script and $stylesheet.
	f, err = rules.NewNetworkRule("@@||test.example^$~script,~stylesheet", 0)
	r = rules.NewRequest(testURLStr, "", rules.TypeScript)
	require.NoError(t, err)
	assert.False(t, f.Match(r))

	r = rules.NewRequest(testURLStr, "", rules.TypeStylesheet)
	require.NoError(t, err)
	assert.False(t, f.Match(r))

	r = rules.NewRequest(testURLStr, "", rules.TypeDocument)
	require.NoError(t, err)
	assert.True(t, f.Match(r))
}

func TestNetworkRule_Match_domainRestrictions(t *testing.T) {
	t.Parallel()

	// Just one permitted domain.
	f, err := rules.NewNetworkRule("||test.example^$domain=test.example", 0)
	r := rules.NewRequest(testURLStr, "", rules.TypeScript)
	require.NoError(t, err)
	assert.False(t, f.Match(r))

	r = rules.NewRequest(testURLStr, testURLStr, rules.TypeScript)
	require.NoError(t, err)
	assert.True(t, f.Match(r))

	r = rules.NewRequest(testURLStr, testURLSubStr, rules.TypeScript)
	require.NoError(t, err)
	assert.True(t, f.Match(r))

	// One permitted, subdomain restricted.
	f, err = rules.NewNetworkRule("||test.example^$domain=test.example|~sub.test.example", 0)
	r = rules.NewRequest(testURLStr, "", rules.TypeScript)
	require.NoError(t, err)
	assert.False(t, f.Match(r))

	r = rules.NewRequest(testURLStr, testURLStr, rules.TypeScript)
	require.NoError(t, err)
	assert.True(t, f.Match(r))

	r = rules.NewRequest(testURLStr, testURLSubStr, rules.TypeScript)
	require.NoError(t, err)
	assert.False(t, f.Match(r))

	// One restricted.
	f, err = rules.NewNetworkRule("||test.example^$domain=~test.example", 0)
	r = rules.NewRequest(testURLStr, "", rules.TypeScript)
	require.NoError(t, err)
	assert.True(t, f.Match(r))

	r = rules.NewRequest(testURLStr, testURLStr, rules.TypeScript)
	require.NoError(t, err)
	assert.False(t, f.Match(r))

	r = rules.NewRequest(testURLStr, testURLSubStr, rules.TypeScript)
	require.NoError(t, err)
	assert.False(t, f.Match(r))

	// Wide restricted.
	f, err = rules.NewNetworkRule("$domain=test.example", 0)
	r = rules.NewRequest(testURLOtherStr, testURLStr, rules.TypeScript)
	require.NoError(t, err)
	assert.True(t, f.Match(r))
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
		wantErrMsg:         "invalid $denyallow value: ~test.example",
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

			f, err := rules.NewNetworkRule(tc.ruleText, 0)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			if tc.wantErrMsg != "" {
				return
			}

			reqURLStr := ""
			if tc.requestURL != nil {
				reqURLStr = tc.requestURL.String()
			}

			sourceURLStr := ""
			if tc.sourceURL != nil {
				sourceURLStr = tc.sourceURL.String()
			}

			// TODO(d.kolyshev): Make NewRequest accept *url.URL.
			r := rules.NewRequest(reqURLStr, sourceURLStr, rules.TypeScript)
			r.IsHostnameRequest = tc.requestForHostname

			tc.want(t, f.Match(r))
		})
	}
}

func TestNetworkRule_Match_wildcardTLDRestrictions(t *testing.T) {
	t.Parallel()

	f, err := rules.NewNetworkRule("||example.org^$domain=example.*", 0)
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

			sourceURLStr := ""
			if tc.sourceURL != nil {
				sourceURLStr = tc.sourceURL.String()
			}

			// TODO(d.kolyshev): Make NewRequest accept *url.URL.
			r := rules.NewRequest(requestURL.String(), sourceURLStr, rules.TypeScript)
			tc.want(t, f.Match(r))
		})
	}
}

func TestNetworkRule_invalidDomainRestrictions(t *testing.T) {
	t.Parallel()

	_, err := rules.NewNetworkRule("||example.org^$domain=", 0)
	assert.Error(t, err)

	_, err = rules.NewNetworkRule("||example.org^$domain=|example.com", 0)
	assert.Error(t, err)
}

func TestNetworkRule_Match_client(t *testing.T) {
	t.Parallel()

	f, err := rules.NewNetworkRule("||test.example^$client=127.0.0.1", 0)
	require.NoError(t, err)
	assert.NotNil(t, f)

	r := rules.NewRequestForHostname(testHostname)
	r.ClientIP = netip.MustParseAddr("127.0.0.1")
	assert.True(t, f.Match(r))

	r.ClientIP = netip.MustParseAddr("127.0.0.2")
	assert.False(t, f.Match(r))

	f, err = rules.NewNetworkRule("||test.example^$client=127.0.0.0/8", 0)
	require.NoError(t, err)
	assert.NotNil(t, f)

	r.ClientIP = netip.MustParseAddr("127.1.1.1")
	assert.True(t, f.Match(r))

	r.ClientIP = netip.MustParseAddr("126.0.0.0")
	assert.False(t, f.Match(r))

	f, err = rules.NewNetworkRule("||test.example^$client=2001::0:00c0:ffee", 0)
	require.NoError(t, err)
	assert.NotNil(t, f)

	r.ClientIP = netip.MustParseAddr("2001::c0:ffee")
	assert.True(t, f.Match(r))

	r.ClientIP = netip.MustParseAddr("2001::c0:ffef")
	assert.False(t, f.Match(r))

	f, err = rules.NewNetworkRule("||test.example^$client=2001::0:00c0:ffee/112", 0)
	require.NoError(t, err)
	assert.NotNil(t, f)

	r.ClientIP = netip.MustParseAddr("2001::0:c0:0")
	assert.True(t, f.Match(r))

	r.ClientIP = netip.MustParseAddr("2001::c1:ffee")
	assert.False(t, f.Match(r))

	f, err = rules.NewNetworkRule("||test.example^$client=~'Frank\\'s laptop'", 0)
	require.NoError(t, err)
	assert.NotNil(t, f)

	r.ClientName = "Frank's laptop"
	assert.False(t, f.Match(r))

	r.ClientName = "Frank's phone"
	assert.True(t, f.Match(r))

	f, err = rules.NewNetworkRule("||test.example^$client=name", 0)
	require.NoError(t, err)
	assert.NotNil(t, f)

	r.ClientIP = netip.MustParseAddr("127.0.0.1")
	r.ClientName = "name"
	assert.True(t, f.Match(r))

	r.ClientIP = netip.MustParseAddr("127.0.0.1")
	r.ClientName = "another-name"
	assert.False(t, f.Match(r))
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

	u := "https://ci.phncdn.com/videos/201809/25/184777011/original/(m=ecuKGgaaaa)(mh=VSmV9NL_iouBcWJJ)4.jpg"
	sourceURL := "https://www.pornhub.com/view_video.php?viewkey=ph5be89d11de4b0"

	r := rules.NewRequest(u, sourceURL, rules.TypeImage)
	ruleText := "|https://$image,media,script,third-party,domain=" +
		"~feedback.pornhub.com|pornhub.com|redtube.com|redtube.com.br|tube8.com|" +
		"tube8.es|tube8.fr|youporn.com|youporngay.com"

	f, err := rules.NewNetworkRule(ruleText, 0)
	require.NoError(t, err)

	assert.True(t, f.Match(r))
}

func TestNetworkRule_invalidRule(t *testing.T) {
	t.Parallel()

	r, err := rules.NewNetworkRule("*$third-party", -1)
	assert.Nil(t, r)
	assert.ErrorIs(t, err, rules.ErrTooWideRule)

	r, err = rules.NewNetworkRule("$third-party", -1)
	assert.Nil(t, r)
	assert.ErrorIs(t, err, rules.ErrTooWideRule)

	r, err = rules.NewNetworkRule("ad$third-party", -1)
	assert.Nil(t, r)
	assert.ErrorIs(t, err, rules.ErrTooWideRule)

	// This one is valid because it has domain restriction.
	r, err = rules.NewNetworkRule("$domain=ya.ru", -1)
	require.NoError(t, err)
	assert.NotNil(t, r)

	// This one is valid because it has $ctag restriction.
	r, err = rules.NewNetworkRule("$ctag=pc", -1)
	require.NoError(t, err)
	assert.NotNil(t, r)

	// This one is valid because it has $client restriction.
	r, err = rules.NewNetworkRule("$client=127.0.0.1", -1)
	require.NoError(t, err)
	assert.NotNil(t, r)

	// This one is valid because it has $client restriction.
	r, err = rules.NewNetworkRule("/$client=127.0.0.1", -1)
	require.NoError(t, err)
	require.NotNil(t, r)

	req := rules.NewRequest(testURLStr, "", rules.TypeOther)
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

			r, err := rules.NewNetworkRule(tc.ruleText, -1)
			require.NoError(t, err)

			tc.want(t, r.IsHostLevelNetworkRule())
		})
	}
}

func TestNetworkRule_Match_ip(t *testing.T) {
	t.Parallel()

	f, err := rules.NewNetworkRule("://104.154.", -1)
	require.NoError(t, err)
	require.True(t, f.IsHostLevelNetworkRule())

	r := rules.NewRequestForHostname("104.154.1.1")
	assert.True(t, f.Match(r))

	r = rules.NewRequestForHostname("1.104.154.1")
	assert.False(t, f.Match(r))

	f, err = rules.NewNetworkRule("/sub.", 0)
	require.NoError(t, err)

	r = rules.NewRequestForHostname("sub.example.org")
	assert.True(t, f.Match(r))
	r = rules.NewRequestForHostname("sub.host.org")
	assert.True(t, f.Match(r))
	r = rules.NewRequestForHostname("sub2.host.org")
	assert.False(t, f.Match(r))
	r = rules.NewRequestForHostname("2sub.host.org")
	assert.False(t, f.Match(r))
}

// compareRulesPriority is a helper function to compare the priority of the two
// given rules.
func compareRulesPriority(tb testing.TB, left, right string, expected bool) {
	tb.Helper()

	l, err := rules.NewNetworkRule(left, -1)
	require.NoError(tb, err)

	r, err := rules.NewNetworkRule(right, -1)
	require.NoError(tb, err)

	assert.Equal(tb, expected, l.IsHigherPriority(r))
}

func TestNetworkRule_Match_dnsType(t *testing.T) {
	t.Parallel()

	req := rules.NewRequestForHostname(testHostname)
	req.DNSType = dns.TypeAAAA

	r, err := rules.NewNetworkRule("||test.example^$dnstype=TXT|AAAA", -1)
	require.NoError(t, err)
	assert.True(t, r.Match(req))

	r, err = rules.NewNetworkRule("||test.example^$dnstype=~TXT|~AAAA", -1)
	require.NoError(t, err)
	assert.False(t, r.Match(req))

	r, err = rules.NewNetworkRule("$dnstype=AAAA", -1)
	require.NoError(t, err)
	assert.True(t, r.Match(req))

	t.Run("parse_errors", func(t *testing.T) {
		_, err = rules.NewNetworkRule("||test.example^$dnstype=", -1)
		assert.Error(t, err)

		_, err = rules.NewNetworkRule("||test.example^$dnstype=TXT|", -1)
		assert.Error(t, err)

		_, err = rules.NewNetworkRule("||test.example^$dnstype=NONE", -1)
		assert.Error(t, err)

		_, err = rules.NewNetworkRule("||test.example^$dnstype=INVALIDTYPE", -1)
		assert.Error(t, err)
	})
}

func BenchmarkNetworkRule_Match(b *testing.B) {
	r, err := rules.NewNetworkRule("||example.org^", testListID)
	require.NoError(b, err)

	req := rules.NewRequestForHostname("example.org")

	var ok bool
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
	//	BenchmarkNetworkRule_Match-16    	 1859527	       646.3 ns/op	       0 B/op	       0 allocs/op
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
