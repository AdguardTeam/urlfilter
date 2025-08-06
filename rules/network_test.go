package rules_test

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkRule_options(t *testing.T) {
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
			} else {
				assert.True(t, f.IsOptionDisabled(tc.option))
			}
		})
	}
}

func TestNetworkRuleOption_Count(t *testing.T) {
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
			assert.Equal(t, tc.option.Count(), tc.want)
		})
	}
}

func TestNetworkRule_disabledOptions(t *testing.T) {
	ruleText := "@@||example.org$document,~extension"

	f, err := rules.NewNetworkRule(ruleText, 0)
	assert.Nil(t, err)
	assert.NotNil(t, f)
	assert.False(t, f.IsOptionEnabled(rules.OptionExtension))
	assert.False(t, f.IsOptionDisabled(rules.OptionExtension))
}

func TestNetworkRule_Match_simpleBasicRules(t *testing.T) {
	// Simple matching rule
	f, err := rules.NewNetworkRule("||example.org^", 0)
	r := rules.NewRequest("https://example.org/", "", rules.TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	f, err = rules.NewNetworkRule("||example.org/*", 0)
	r = rules.NewRequest("https://example.org/", "", rules.TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	// Subdomains / domains
	f, err = rules.NewNetworkRule("||github.com^", 0)
	r = rules.NewRequestForHostname("dualstack.log.github.com-east-1.elb.amazonaws.com")
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	r = rules.NewRequestForHostname("dualstack.log.github.com1-east-1.elb.amazonaws.com")
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	// Simple regex rule
	f, err = rules.NewNetworkRule("/example\\.org/", 0)
	r = rules.NewRequest("https://example.org/", "", rules.TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	// Simple pattern rule
	f, err = rules.NewNetworkRule("_prebid_", 0)
	r = rules.NewRequest(
		"https://ap.lijit.com/rtb/bid?src=prebid_prebid_1.35.0",
		"https://www.drudgereport.com/",
		rules.TypeXmlhttprequest,
	)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))
}

func TestNetworkRule_invalidModifiers(t *testing.T) {
	_, err := rules.NewNetworkRule("||example.org^$unknown", 0)
	assert.NotNil(t, err)

	// Whitelist-only modifier
	_, err = rules.NewNetworkRule("||example.org^$elemhide", 0)
	assert.NotNil(t, err)

	// Blacklist-only modifier
	_, err = rules.NewNetworkRule("@@||example.org^$popup", 0)
	assert.NotNil(t, err)
}

func TestNetworkRule_Match_case(t *testing.T) {
	f, err := rules.NewNetworkRule("||example.org^$match-case", 0)
	r := rules.NewRequest("https://example.org/", "", rules.TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = rules.NewRequest("https://EXAMPLE.org/", "", rules.TypeOther)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))
}

func TestNetworkRule_Match_thirdParty(t *testing.T) {
	f, err := rules.NewNetworkRule("||example.org^$third-party", 0)

	// First-party 1
	r := rules.NewRequest("https://example.org/", "", rules.TypeOther)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	// First-party 2
	r = rules.NewRequest("https://sub.example.org/", "https://example.org/", rules.TypeOther)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	// Third-party
	r = rules.NewRequest("https://example.org/", "https://example.com", rules.TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	f, err = rules.NewNetworkRule("||example.org^$first-party", 0)

	// First-party 1
	r = rules.NewRequest("https://example.org/", "", rules.TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	// First-party
	r = rules.NewRequest("https://sub.example.org/", "https://example.org/", rules.TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	// Third-party
	r = rules.NewRequest("https://example.org/", "https://example.com", rules.TypeOther)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))
}

func TestNetworkRule_Match_contentType(t *testing.T) {
	// $script
	f, err := rules.NewNetworkRule("||example.org^$script", 0)
	r := rules.NewRequest("https://example.org/", "", rules.TypeScript)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = rules.NewRequest("https://example.org/", "", rules.TypeDocument)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	// $script and $stylesheet
	f, err = rules.NewNetworkRule("||example.org^$script,stylesheet", 0)
	r = rules.NewRequest("https://example.org/", "", rules.TypeScript)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = rules.NewRequest("https://example.org/", "", rules.TypeStylesheet)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = rules.NewRequest("https://example.org/", "", rules.TypeDocument)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	// Everything except $script and $stylesheet
	f, err = rules.NewNetworkRule("@@||example.org^$~script,~stylesheet", 0)
	r = rules.NewRequest("https://example.org/", "", rules.TypeScript)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	r = rules.NewRequest("https://example.org/", "", rules.TypeStylesheet)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	r = rules.NewRequest("https://example.org/", "", rules.TypeDocument)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))
}

func TestNetworkRule_Match_domainRestrictions(t *testing.T) {
	// Just one permitted domain
	f, err := rules.NewNetworkRule("||example.org^$domain=example.org", 0)
	r := rules.NewRequest("https://example.org/", "", rules.TypeScript)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	r = rules.NewRequest("https://example.org/", "https://example.org/", rules.TypeScript)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = rules.NewRequest("https://example.org/", "https://subdomain.example.org/", rules.TypeScript)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	// One permitted, subdomain restricted
	f, err = rules.NewNetworkRule("||example.org^$domain=example.org|~subdomain.example.org", 0)
	r = rules.NewRequest("https://example.org/", "", rules.TypeScript)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	r = rules.NewRequest("https://example.org/", "https://example.org/", rules.TypeScript)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = rules.NewRequest("https://example.org/", "https://subdomain.example.org/", rules.TypeScript)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	// One restricted
	f, err = rules.NewNetworkRule("||example.org^$domain=~example.org", 0)
	r = rules.NewRequest("https://example.org/", "", rules.TypeScript)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = rules.NewRequest("https://example.org/", "https://example.org/", rules.TypeScript)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	r = rules.NewRequest("https://example.org/", "https://subdomain.example.org/", rules.TypeScript)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	// Wide restricted
	f, err = rules.NewNetworkRule("$domain=example.org", 0)
	r = rules.NewRequest("https://example.com/", "https://example.org/", rules.TypeScript)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))
}

func TestNetworkRule_Match_denyallow(t *testing.T) {
	testCases := []struct {
		testName           string
		ruleText           string
		requestURL         string
		sourceURL          string
		requestForHostname bool
		fail               bool
		match              bool
	}{
		{
			testName: "denyallow_invalid_inversion",
			ruleText: "*^$denyallow=~example.org",
			fail:     true,
		},
		{
			testName: "denyallow_invalid_empty",
			ruleText: "*^$denyallow",
			fail:     true,
		},
		{
			testName:   "denyallow_unblock_tld",
			ruleText:   "*^$denyallow=org",
			requestURL: "https://example.org/",
			fail:       false,
			match:      false,
		},
		{
			testName:   "denyallow_found",
			ruleText:   "*^$denyallow=example.org",
			requestURL: "https://example.org/",
			fail:       false,
			match:      false,
		},
		{
			testName:   "denyallow_found_subdomain",
			ruleText:   "*^$denyallow=example.org",
			requestURL: "https://sub.example.org/",
			fail:       false,
			match:      false,
		},
		{
			testName:   "denyallow_not_found",
			ruleText:   "*^$denyallow=example.org",
			requestURL: "https://example.net/",
			fail:       false,
			match:      true,
		},
		{
			testName:   "denyallow_found_multiple_domains",
			ruleText:   "*^$denyallow=example.org|example.net",
			requestURL: "https://example.org/",
			fail:       false,
			match:      false,
		},
		{
			testName:   "denyallow_found_multiple_domains",
			ruleText:   "*^$denyallow=example.org|example.net",
			requestURL: "https://example.net/",
			fail:       false,
			match:      false,
		},
		{
			testName:   "denyallow_and_domain_blocking",
			ruleText:   "*^$domain=example.org,denyallow=essentialdomain.net",
			requestURL: "https://example.net/",
			sourceURL:  "https://example.org/",
			fail:       false,
			match:      true,
		},
		{
			testName:   "denyallow_and_domain_not_blocking",
			ruleText:   "*^$domain=example.org,denyallow=essentialdomain.net",
			requestURL: "https://essentialdomain.net/",
			sourceURL:  "https://example.org/",
			fail:       false,
			match:      false,
		},
		{
			testName:           "denyallow_does_not_match_ips",
			ruleText:           "*$denyallow=com",
			requestURL:         "https://192.168.1.1/",
			requestForHostname: true,
			fail:               false,
			match:              false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			f, err := rules.NewNetworkRule(tc.ruleText, 0)
			if tc.fail {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			r := rules.NewRequest(tc.requestURL, tc.sourceURL, rules.TypeScript)
			r.IsHostnameRequest = tc.requestForHostname
			require.Equal(t, tc.match, f.Match(r))
		})
	}
}

func TestNetworkRule_Match_wildcardTLDRestrictions(t *testing.T) {
	f, err := rules.NewNetworkRule("||example.org^$domain=example.*", 0)
	assert.Nil(t, err)

	r := rules.NewRequest("https://example.org/", "", rules.TypeScript)
	assert.False(t, f.Match(r))

	r = rules.NewRequest("https://example.org/", "https://example.com/", rules.TypeScript)
	assert.True(t, f.Match(r))

	r = rules.NewRequest("https://example.org/", "https://example.co.uk/", rules.TypeScript)
	assert.True(t, f.Match(r))

	r = rules.NewRequest("https://example.org/", "https://test.example.co.uk/", rules.TypeScript)
	assert.True(t, f.Match(r))

	// Not a public suffix
	r = rules.NewRequest("https://example.org/", "https://example.local/", rules.TypeScript)
	assert.False(t, f.Match(r))

	// Not a public suffix
	r = rules.NewRequest("https://example.org/", "https://example.test.test/", rules.TypeScript)
	assert.False(t, f.Match(r))
}

func TestNetworkRule_invalidDomainRestrictions(t *testing.T) {
	_, err := rules.NewNetworkRule("||example.org^$domain=", 0)
	assert.NotNil(t, err)

	_, err = rules.NewNetworkRule("||example.org^$domain=|example.com", 0)
	assert.NotNil(t, err)
}

func TestNetworkRule_Match_client(t *testing.T) {
	f, err := rules.NewNetworkRule("||example.org^$client=127.0.0.1", 0)
	assert.Nil(t, err)
	assert.NotNil(t, f)

	r := rules.NewRequestForHostname("example.org")
	r.ClientIP = netip.MustParseAddr("127.0.0.1")
	assert.True(t, f.Match(r))

	r.ClientIP = netip.MustParseAddr("127.0.0.2")
	assert.False(t, f.Match(r))

	f, err = rules.NewNetworkRule("||example.org^$client=127.0.0.0/8", 0)
	assert.Nil(t, err)
	assert.NotNil(t, f)

	r.ClientIP = netip.MustParseAddr("127.1.1.1")
	assert.True(t, f.Match(r))

	r.ClientIP = netip.MustParseAddr("126.0.0.0")
	assert.False(t, f.Match(r))

	f, err = rules.NewNetworkRule("||example.org^$client=2001::0:00c0:ffee", 0)
	assert.Nil(t, err)
	assert.NotNil(t, f)

	r.ClientIP = netip.MustParseAddr("2001::c0:ffee")
	assert.True(t, f.Match(r))

	r.ClientIP = netip.MustParseAddr("2001::c0:ffef")
	assert.False(t, f.Match(r))

	f, err = rules.NewNetworkRule("||example.org^$client=2001::0:00c0:ffee/112", 0)
	assert.Nil(t, err)
	assert.NotNil(t, f)

	r.ClientIP = netip.MustParseAddr("2001::0:c0:0")
	assert.True(t, f.Match(r))

	r.ClientIP = netip.MustParseAddr("2001::c1:ffee")
	assert.False(t, f.Match(r))

	f, err = rules.NewNetworkRule("||example.org^$client=~'Frank\\'s laptop'", 0)
	assert.Nil(t, err)
	assert.NotNil(t, f)

	r.ClientName = "Frank's laptop"
	assert.False(t, f.Match(r))

	r.ClientName = "Frank's phone"
	assert.True(t, f.Match(r))

	f, err = rules.NewNetworkRule("||example.org^$client=name", 0)
	assert.Nil(t, err)
	assert.NotNil(t, f)

	r.ClientIP = netip.MustParseAddr("127.0.0.1")
	r.ClientName = "name"
	assert.True(t, f.Match(r))

	r.ClientIP = netip.MustParseAddr("127.0.0.1")
	r.ClientName = "another-name"
	assert.False(t, f.Match(r))
}

func TestNetworkRule_IsHigherPriority(t *testing.T) {
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
	url := "https://ci.phncdn.com/videos/201809/25/184777011/original/(m=ecuKGgaaaa)(mh=VSmV9NL_iouBcWJJ)4.jpg"
	sourceURL := "https://www.pornhub.com/view_video.php?viewkey=ph5be89d11de4b0"

	r := rules.NewRequest(url, sourceURL, rules.TypeImage)
	ruleText := "|https://$image,media,script,third-party,domain=~feedback.pornhub.com|pornhub.com|redtube.com|redtube.com.br|tube8.com|tube8.es|tube8.fr|youporn.com|youporngay.com"
	f, err := rules.NewNetworkRule(ruleText, 0)
	if err != nil {
		t.Fatalf("failed to create rule: %s", err)
	}

	assert.True(t, f.Match(r))
}

func TestNetworkRule_invalidRule(t *testing.T) {
	r, err := rules.NewNetworkRule("*$third-party", -1)
	assert.Nil(t, r)
	assert.Equal(t, rules.ErrTooWideRule, err)

	r, err = rules.NewNetworkRule("$third-party", -1)
	assert.Nil(t, r)
	assert.Equal(t, rules.ErrTooWideRule, err)

	r, err = rules.NewNetworkRule("ad$third-party", -1)
	assert.Nil(t, r)
	assert.Equal(t, rules.ErrTooWideRule, err)

	// This one is valid because it has domain restriction
	r, err = rules.NewNetworkRule("$domain=ya.ru", -1)
	assert.NotNil(t, r)
	assert.Nil(t, err)

	// This one is valid because it has $ctag restriction
	r, err = rules.NewNetworkRule("$ctag=pc", -1)
	assert.NotNil(t, r)
	assert.Nil(t, err)

	// This one is valid because it has $client restriction
	r, err = rules.NewNetworkRule("$client=127.0.0.1", -1)
	assert.NotNil(t, r)
	assert.Nil(t, err)

	// This one is valid because it has $client restriction
	r, err = rules.NewNetworkRule("/$client=127.0.0.1", -1)
	require.NotNil(t, r)
	require.NoError(t, err)

	req := rules.NewRequest("https://example.org/", "", rules.TypeOther)
	req.ClientIP = netip.MustParseAddr("127.0.0.1")
	assert.True(t, r.Match(req))
}

func TestNetworkRule_IsHostLevelNetworkRule(t *testing.T) {
	r, err := rules.NewNetworkRule("||example.org^$important", -1)
	assert.Nil(t, err)
	assert.True(t, r.IsHostLevelNetworkRule())

	r, err = rules.NewNetworkRule("||example.org^$important,badfilter", -1)
	assert.Nil(t, err)
	assert.True(t, r.IsHostLevelNetworkRule())

	r, err = rules.NewNetworkRule("||example.org^$badfilter", -1)
	assert.Nil(t, err)
	assert.True(t, r.IsHostLevelNetworkRule())

	r, err = rules.NewNetworkRule("||example.org^", -1)
	assert.Nil(t, err)
	assert.True(t, r.IsHostLevelNetworkRule())

	r, err = rules.NewNetworkRule("||example.org^$~third-party", -1)
	assert.Nil(t, err)
	assert.False(t, r.IsHostLevelNetworkRule())

	r, err = rules.NewNetworkRule("||example.org^$third-party", -1)
	assert.Nil(t, err)
	assert.False(t, r.IsHostLevelNetworkRule())

	r, err = rules.NewNetworkRule("||example.org^$domain=example.com", -1)
	assert.Nil(t, err)
	assert.False(t, r.IsHostLevelNetworkRule())
}

func TestNetworkRule_Match_ip(t *testing.T) {
	f, err := rules.NewNetworkRule("://104.154.", -1)
	assert.Nil(t, err)
	assert.True(t, f.IsHostLevelNetworkRule())

	r := rules.NewRequestForHostname("104.154.1.1")
	assert.True(t, f.Match(r))

	r = rules.NewRequestForHostname("1.104.154.1")
	assert.False(t, f.Match(r))

	f, err = rules.NewNetworkRule("/sub.", 0)
	assert.Nil(t, err)
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
	req := rules.NewRequestForHostname("example.org")
	req.DNSType = dns.TypeAAAA

	r, err := rules.NewNetworkRule("||example.org^$dnstype=TXT|AAAA", -1)
	assert.Nil(t, err)
	assert.True(t, r.Match(req))

	r, err = rules.NewNetworkRule("||example.org^$dnstype=~TXT|~AAAA", -1)
	assert.Nil(t, err)
	assert.False(t, r.Match(req))

	r, err = rules.NewNetworkRule("$dnstype=AAAA", -1)
	assert.Nil(t, err)
	assert.True(t, r.Match(req))

	t.Run("parse_errors", func(t *testing.T) {
		_, err = rules.NewNetworkRule("||example.org^$dnstype=", -1)
		assert.NotNil(t, err)

		_, err = rules.NewNetworkRule("||example.org^$dnstype=TXT|", -1)
		assert.NotNil(t, err)

		_, err = rules.NewNetworkRule("||example.org^$dnstype=NONE", -1)
		assert.NotNil(t, err)

		_, err = rules.NewNetworkRule("||example.org^$dnstype=INVALIDTYPE", -1)
		assert.NotNil(t, err)
	})
}

func FuzzNetworkRule_Match(f *testing.F) {
	r, err := rules.NewNetworkRule("||example.org^", testFilterListID)
	require.NoError(f, err)

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

	f.Fuzz(func(t *testing.T, domain string) {
		req := rules.NewRequestForHostname(domain)

		assert.NotPanics(t, func() {
			_ = r.Match(req)
		})
	})
}
