package rules_test

import (
	"fmt"
	"net/netip"
	"net/url"
	"testing"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter/internal/geoip"
	"github.com/AdguardTeam/urlfilter/internal/uftest"
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

			r := uftest.NewNetworkRule(t, ruleText)
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

	r := uftest.NewNetworkRule(t, ruleText)
	assert.False(t, r.IsOptionEnabled(rules.OptionExtension))
	assert.False(t, r.IsOptionDisabled(rules.OptionExtension))
}

func TestNetworkRule_Match_simpleBasicRules(t *testing.T) {
	t.Parallel()

	// Simple matching rule.
	r := uftest.NewNetworkRule(t, uftest.RuleHost)
	req := rules.NewRequest(uftest.URLStrHost, "", rules.TypeOther)
	assert.True(t, r.Match(req))

	r = uftest.NewNetworkRule(t, "||"+uftest.Host+"/*")
	req = rules.NewRequest(uftest.URLStrHost, "", rules.TypeOther)
	assert.True(t, r.Match(req))

	// Subdomains / domains.
	r = uftest.NewNetworkRule(t, "||github.com^")
	req = rules.NewRequestForHostname("dualstack.log.github.com-east-1.elb.amazonaws.com")
	assert.False(t, r.Match(req))

	req = rules.NewRequestForHostname("dualstack.log.github.com1-east-1.elb.amazonaws.com")
	assert.False(t, r.Match(req))

	// Simple regex rule.
	r = uftest.NewNetworkRule(t, `/host\.example/`)
	req = rules.NewRequest(uftest.URLStrHost, "", rules.TypeOther)
	assert.True(t, r.Match(req))

	// Simple pattern rule.
	r = uftest.NewNetworkRule(t, "_prebid_")
	req = rules.NewRequest(
		"https://ap.lijit.com/rtb/bid?src=prebid_prebid_1.35.0",
		"https://www.drudgereport.com/",
		rules.TypeXmlhttprequest,
	)
	assert.True(t, r.Match(req))
}

func TestNetworkRule_invalidModifiers(t *testing.T) {
	t.Parallel()

	r, err := rules.NewNetworkRule("||example.org^$unknown", uftest.ListID1)
	assert.Error(t, err)
	assert.Nil(t, r)

	// Whitelist-only modifier.
	r, err = rules.NewNetworkRule("||example.org^$elemhide", uftest.ListID1)
	assert.Error(t, err)
	assert.Nil(t, r)

	// Blacklist-only modifier.
	r, err = rules.NewNetworkRule("@@||example.org^$popup", uftest.ListID1)
	assert.Error(t, err)
	assert.Nil(t, r)
}

func TestNetworkRule_Match_case(t *testing.T) {
	t.Parallel()

	r := uftest.NewNetworkRule(t, uftest.RuleHost+"$match-case")
	req := rules.NewRequest(uftest.URLStrHost, "", rules.TypeOther)
	assert.True(t, r.Match(req))

	req = rules.NewRequest("https://EXAMPLE.org/", "", rules.TypeOther)
	assert.False(t, r.Match(req))
}

func TestNetworkRule_Match_thirdParty(t *testing.T) {
	t.Parallel()

	r := uftest.NewNetworkRule(t, uftest.RuleHost+"$third-party")

	// First-party 1.
	req := rules.NewRequest(uftest.URLStrHost, "", rules.TypeOther)
	assert.False(t, r.Match(req))

	// First-party 2.
	req = rules.NewRequest(uftest.URLStrHostSub, uftest.URLStrHost, rules.TypeOther)
	assert.False(t, r.Match(req))

	// Third-party.
	req = rules.NewRequest(uftest.URLStrHost, uftest.URLStrHostOther, rules.TypeOther)
	assert.True(t, r.Match(req))

	r = uftest.NewNetworkRule(t, uftest.RuleHost+"$first-party")

	// First-party 1.
	req = rules.NewRequest(uftest.URLStrHost, "", rules.TypeOther)
	assert.True(t, r.Match(req))

	// First-party.
	req = rules.NewRequest(uftest.URLStrHostSub, uftest.URLStrHost, rules.TypeOther)
	assert.True(t, r.Match(req))

	// Third-party.
	req = rules.NewRequest(uftest.URLStrHost, uftest.URLStrHostOther, rules.TypeOther)
	assert.False(t, r.Match(req))
}

func TestNetworkRule_Match_contentType(t *testing.T) {
	t.Parallel()

	// $script.
	r := uftest.NewNetworkRule(t, uftest.RuleHost+"$script")
	req := rules.NewRequest(uftest.URLStrHost, "", rules.TypeScript)
	assert.True(t, r.Match(req))

	req = rules.NewRequest(uftest.URLStrHost, "", rules.TypeDocument)
	assert.False(t, r.Match(req))

	// $script and $stylesheet.
	r = uftest.NewNetworkRule(t, uftest.RuleHost+"$script,stylesheet")
	req = rules.NewRequest(uftest.URLStrHost, "", rules.TypeScript)
	assert.True(t, r.Match(req))

	req = rules.NewRequest(uftest.URLStrHost, "", rules.TypeStylesheet)
	assert.True(t, r.Match(req))

	req = rules.NewRequest(uftest.URLStrHost, "", rules.TypeDocument)
	assert.False(t, r.Match(req))

	// Everything except $script and $stylesheet.
	r = uftest.NewNetworkRule(t, "@@"+uftest.RuleHost+"$~script,~stylesheet")
	req = rules.NewRequest(uftest.URLStrHost, "", rules.TypeScript)
	assert.False(t, r.Match(req))

	req = rules.NewRequest(uftest.URLStrHost, "", rules.TypeStylesheet)
	assert.False(t, r.Match(req))

	req = rules.NewRequest(uftest.URLStrHost, "", rules.TypeDocument)
	assert.True(t, r.Match(req))
}

func TestNetworkRule_Match_domainRestrictions(t *testing.T) {
	t.Parallel()

	// Just one permitted domain.
	r := uftest.NewNetworkRule(t, uftest.RuleHost+"$domain="+uftest.Host)
	req := rules.NewRequest(uftest.URLStrHost, "", rules.TypeScript)
	assert.False(t, r.Match(req))

	req = rules.NewRequest(uftest.URLStrHost, uftest.URLStrHost, rules.TypeScript)
	assert.True(t, r.Match(req))

	req = rules.NewRequest(uftest.URLStrHost, uftest.URLStrHostSub, rules.TypeScript)
	assert.True(t, r.Match(req))

	// One permitted, subdomain restricted.
	r = uftest.NewNetworkRule(t, uftest.RuleHost+"$domain="+uftest.Host+"|~"+uftest.HostSub)
	req = rules.NewRequest(uftest.URLStrHost, "", rules.TypeScript)
	assert.False(t, r.Match(req))

	req = rules.NewRequest(uftest.URLStrHost, uftest.URLStrHost, rules.TypeScript)
	assert.True(t, r.Match(req))

	req = rules.NewRequest(uftest.URLStrHost, uftest.URLStrHostSub, rules.TypeScript)
	assert.False(t, r.Match(req))

	// One restricted.
	r = uftest.NewNetworkRule(t, uftest.RuleHost+"$domain=~"+uftest.Host)
	req = rules.NewRequest(uftest.URLStrHost, "", rules.TypeScript)
	assert.True(t, r.Match(req))

	req = rules.NewRequest(uftest.URLStrHost, uftest.URLStrHost, rules.TypeScript)
	assert.False(t, r.Match(req))

	req = rules.NewRequest(uftest.URLStrHost, uftest.URLStrHostSub, rules.TypeScript)
	assert.False(t, r.Match(req))

	// Wide restricted.
	r = uftest.NewNetworkRule(t, "$domain="+uftest.Host)
	req = rules.NewRequest(uftest.URLStrHostOther, uftest.URLStrHost, rules.TypeScript)
	assert.True(t, r.Match(req))
}

func TestNetworkRule_Match_respgeoCountry(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		wantMatch  assert.BoolAssertionFunc
		name       string
		rule       string
		reqCountry geoip.Country
	}{{
		name:       "permit_country",
		rule:       uftest.CountryFR,
		reqCountry: uftest.CountryFR,
		wantMatch:  assert.True,
	}, {
		name:       "permit_country_case_insensitive",
		rule:       uftest.CountryFR,
		reqCountry: "fr",
		wantMatch:  assert.True,
	}, {
		name:       "permit_country_mismatch",
		rule:       uftest.CountryFR,
		reqCountry: uftest.CountryRU,
		wantMatch:  assert.False,
	}, {
		name:       "restrict_country",
		rule:       "~" + uftest.CountryFR,
		reqCountry: uftest.CountryFR,
		wantMatch:  assert.False,
	}, {
		name:       "restrict_country_mismatch",
		rule:       "~" + uftest.CountryFR,
		reqCountry: uftest.CountryRU,
		wantMatch:  assert.True,
	}, {
		name:       "restrict_multiple_countries",
		rule:       "~" + uftest.CountryFR + "|~" + uftest.CountryRU,
		reqCountry: uftest.CountryRU,
		wantMatch:  assert.False,
	}, {
		name:       "restrict_multiple_countries_mismatch",
		rule:       "~" + uftest.CountryFR + "|~" + uftest.CountryRU,
		reqCountry: uftest.CountryDE,
		wantMatch:  assert.True,
	}, {
		name:       "permit_multiple_countries",
		rule:       uftest.CountryFR + "|" + uftest.CountryRU,
		reqCountry: uftest.CountryRU,
		wantMatch:  assert.True,
	}, {
		name:       "permit_multiple_countries_mismatch",
		rule:       uftest.CountryFR + "|" + uftest.CountryRU,
		reqCountry: uftest.CountryDE,
		wantMatch:  assert.False,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assertGeoIPMatch(t, tc.rule, tc.reqCountry, geoip.ASNUnknown, tc.wantMatch)
		})
	}
}

// assertGeoIPMatch asserts that the specified rule matches the request with the
// given country and ASN using the provided assertion function.
func assertGeoIPMatch(
	tb testing.TB,
	rule string,
	country geoip.Country,
	asn geoip.ASN,
	wantMatch assert.BoolAssertionFunc,
) {
	tb.Helper()

	r := uftest.NewNetworkRule(tb, uftest.RuleHost+"$respgeo="+rule)
	req := rules.NewRequest(uftest.URLStrHost, "", rules.TypeScript)
	req.ClientCountry = country
	req.ClientASN = asn
	wantMatch(tb, r.Match(req))
}

func TestNetworkRule_Match_respgeoASN(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		wantMatch assert.BoolAssertionFunc
		name      string
		rule      string
		reqASN    geoip.ASN
	}{{
		name:      "permit_asn",
		rule:      uftest.ASN1Str,
		reqASN:    uftest.ASN1,
		wantMatch: assert.True,
	}, {
		name:      "permit_asn_mismatch",
		rule:      uftest.ASN1Str,
		reqASN:    uftest.ASN2,
		wantMatch: assert.False,
	}, {
		name:      "restrict_asn",
		rule:      "~" + uftest.ASN1Str,
		reqASN:    uftest.ASN1,
		wantMatch: assert.False,
	}, {
		name:      "restrict_asn_mismatch",
		rule:      "~" + uftest.ASN1Str,
		reqASN:    uftest.ASN2,
		wantMatch: assert.True,
	}, {
		name:      "restrict_multiple_asns",
		rule:      "~" + uftest.ASN1Str + "|~" + uftest.ASN2Str,
		reqASN:    uftest.ASN1,
		wantMatch: assert.False,
	}, {
		name:      "restrict_multiple_asns_mismatch",
		rule:      "~" + uftest.ASN1Str + "|~" + uftest.ASN2Str,
		reqASN:    uftest.ASN2,
		wantMatch: assert.False,
	}, {
		name:      "permit_multiple_asns",
		rule:      uftest.ASN1Str + "|" + uftest.ASN2Str,
		reqASN:    uftest.ASN1,
		wantMatch: assert.True,
	}, {
		name:      "permit_multiple_asns_mismatch",
		rule:      uftest.ASN1Str + "|" + uftest.ASN2Str,
		reqASN:    123,
		wantMatch: assert.False,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assertGeoIPMatch(t, tc.rule, geoip.CountryUnknown, tc.reqASN, tc.wantMatch)
		})
	}
}

func TestNetworkRule_Match_respgeoOther(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		wantMatch  assert.BoolAssertionFunc
		name       string
		rule       string
		reqCountry geoip.Country
		reqASN     geoip.ASN
	}{{
		name:       "permit_unknown",
		rule:       "",
		reqCountry: geoip.CountryUnknown,
		reqASN:     geoip.ASNUnknown,
		wantMatch:  assert.True,
	}, {
		name:       "permit_unknown_mismatch",
		rule:       "",
		reqCountry: uftest.CountryDE,
		reqASN:     geoip.ASNUnknown,
		wantMatch:  assert.False,
	}, {
		name:       "restrict_unknown",
		rule:       "~",
		reqCountry: geoip.CountryUnknown,
		reqASN:     geoip.ASNUnknown,
		wantMatch:  assert.False,
	}, {
		name:       "restrict_country_unknown_mismatch",
		rule:       "~",
		reqCountry: geoip.CountryUnknown,
		reqASN:     uftest.ASN1,
		wantMatch:  assert.True,
	}, {
		name:       "restrict_country_and_asn_unknown_mismatch",
		rule:       "~",
		reqCountry: uftest.CountryRU,
		reqASN:     uftest.ASN1,
		wantMatch:  assert.True,
	}, {
		name:       "restrict_and_permit_unknown",
		rule:       "~|",
		reqCountry: geoip.CountryUnknown,
		reqASN:     geoip.ASNUnknown,
		wantMatch:  assert.True,
	}, {
		name:       "partial_asn_match",
		rule:       uftest.ASN1Str + "|" + uftest.CountryDE,
		reqCountry: uftest.CountryFR,
		reqASN:     uftest.ASN1,
		wantMatch:  assert.True,
	}, {
		name:       "partial_country_match",
		rule:       uftest.ASN1Str + "|" + uftest.CountryDE,
		reqCountry: uftest.CountryDE,
		reqASN:     uftest.ASN2,
		wantMatch:  assert.True,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assertGeoIPMatch(t, tc.rule, tc.reqCountry, tc.reqASN, tc.wantMatch)
		})
	}
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
		ruleText:           "*^$denyallow=~" + uftest.Host,
		wantErrMsg:         `invalid $denyallow value: "~` + uftest.Host + `"`,
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
		ruleText:           "*^$denyallow=" + uftest.Host,
		wantErrMsg:         "",
		requestForHostname: false,
	}, {
		want:               assert.False,
		requestURL:         testURLSub,
		sourceURL:          nil,
		testName:           "denyallow_found_subdomain",
		ruleText:           "*^$denyallow=" + uftest.Host,
		wantErrMsg:         "",
		requestForHostname: false,
	}, {
		want:               assert.True,
		requestURL:         testURLOther,
		sourceURL:          nil,
		testName:           "denyallow_not_found",
		ruleText:           "*^$denyallow=" + uftest.Host,
		wantErrMsg:         "",
		requestForHostname: false,
	}, {
		want:               assert.False,
		requestURL:         testURL,
		sourceURL:          nil,
		testName:           "denyallow_found_multiple_domains",
		ruleText:           "*^$denyallow=" + uftest.Host + "|" + uftest.HostOther,
		wantErrMsg:         "",
		requestForHostname: false,
	}, {
		want:               assert.True,
		requestURL:         testURLOther,
		sourceURL:          testURL,
		testName:           "denyallow_and_domain_blocking",
		ruleText:           "*^$domain=" + uftest.Host + ",denyallow=essentialdomain.net",
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
		ruleText:           "*^$domain=" + uftest.Host + ",denyallow=essentialdomain.net",
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

			r, err := rules.NewNetworkRule(tc.ruleText, uftest.ListID1)
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
			req := rules.NewRequest(reqURLStr, sourceURLStr, rules.TypeScript)
			req.IsHostnameRequest = tc.requestForHostname

			tc.want(t, r.Match(req))
		})
	}
}

func TestNetworkRule_Match_wildcardTLDRestrictions(t *testing.T) {
	t.Parallel()

	r := uftest.NewNetworkRule(t, "||example.org^$domain=example.*")

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
			req := rules.NewRequest(requestURL.String(), sourceURLStr, rules.TypeScript)
			tc.want(t, r.Match(req))
		})
	}
}

func TestNetworkRule_invalidDomainRestrictions(t *testing.T) {
	t.Parallel()

	_, err := rules.NewNetworkRule("||example.org^$domain=", uftest.ListID1)
	assert.Error(t, err)

	_, err = rules.NewNetworkRule("||example.org^$domain=|example.com", uftest.ListID1)
	assert.Error(t, err)
}

func TestNetworkRule_Match_client(t *testing.T) {
	t.Parallel()

	r := uftest.NewNetworkRule(t, uftest.RuleHost+"$client=127.0.0.1")

	req := rules.NewRequestForHostname(uftest.Host)
	req.ClientIP = netip.MustParseAddr("127.0.0.1")
	assert.True(t, r.Match(req))

	req.ClientIP = netip.MustParseAddr("127.0.0.2")
	assert.False(t, r.Match(req))

	r = uftest.NewNetworkRule(t, uftest.RuleHost+"$client=127.0.0.0/8")

	req.ClientIP = netip.MustParseAddr("127.1.1.1")
	assert.True(t, r.Match(req))

	req.ClientIP = netip.MustParseAddr("126.0.0.0")
	assert.False(t, r.Match(req))

	r = uftest.NewNetworkRule(t, uftest.RuleHost+"$client=2001::0:00c0:ffee")

	req.ClientIP = netip.MustParseAddr("2001::c0:ffee")
	assert.True(t, r.Match(req))

	req.ClientIP = netip.MustParseAddr("2001::c0:ffef")
	assert.False(t, r.Match(req))

	r = uftest.NewNetworkRule(t, uftest.RuleHost+"$client=2001::0:00c0:ffee/112")

	req.ClientIP = netip.MustParseAddr("2001::0:c0:0")
	assert.True(t, r.Match(req))

	req.ClientIP = netip.MustParseAddr("2001::c1:ffee")
	assert.False(t, r.Match(req))

	r = uftest.NewNetworkRule(t, uftest.RuleHost+`$client=~'Frank's laptop'`)

	req.ClientIdentifiers = container.NewSortedSliceSet("Frank's laptop")
	assert.False(t, r.Match(req))

	req.ClientIdentifiers = container.NewSortedSliceSet("Frank's phone")
	assert.True(t, r.Match(req))

	r = uftest.NewNetworkRule(t, uftest.RuleHost+"$client=name")

	req.ClientIP = netip.MustParseAddr("127.0.0.1")
	req.ClientIdentifiers = container.NewSortedSliceSet("name")
	assert.True(t, r.Match(req))

	req.ClientIP = netip.MustParseAddr("127.0.0.1")
	req.ClientIdentifiers = container.NewSortedSliceSet("another-name")
	assert.False(t, r.Match(req))

	r = uftest.NewNetworkRule(t, `0$client=127.0.0.1`)
	assert.False(t, r.Match(req))

	r = uftest.NewNetworkRule(t, "^$client=127.0.0.1")
	assert.False(t, r.Match(req))
}

func TestNetworkRule_IsHigherPriority(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		want  assert.BoolAssertionFunc
		left  string
		right string
	}{{
		want:  assert.False,
		left:  "@@||example.org$important",
		right: "@@||example.org$important",
	}, {
		want:  assert.True,
		left:  "@@||example.org$important",
		right: "||example.org$important",
	}, {
		want:  assert.True,
		left:  "@@||example.org$important",
		right: "@@||example.org",
	}, {
		want:  assert.True,
		left:  "@@||example.org$important",
		right: "||example.org",
	}, {
		want:  assert.False,
		left:  "||example.org$important",
		right: "@@||example.org$important",
	}, {
		want:  assert.False,
		left:  "||example.org$important",
		right: "||example.org$important",
	}, {
		want:  assert.True,
		left:  "||example.org$important",
		right: "@@||example.org",
	}, {
		want:  assert.True,
		left:  "||example.org$important",
		right: "||example.org",
	}, {
		want:  assert.False,
		left:  "@@||example.org",
		right: "@@||example.org$important",
	}, {
		want:  assert.False,
		left:  "@@||example.org",
		right: "||example.org$important",
	}, {
		want:  assert.False,
		left:  "@@||example.org",
		right: "@@||example.org",
	}, {
		want:  assert.True,
		left:  "@@||example.org",
		right: "||example.org",
	}, {
		want:  assert.False,
		left:  "||example.org",
		right: "@@||example.org$important",
	}, {
		want:  assert.False,
		left:  "||example.org",
		right: "||example.org$important",
	}, {
		want:  assert.False,
		left:  "||example.org",
		right: "@@||example.org",
	}, {
		want:  assert.False,
		left:  "||example.org",
		right: "||example.org",
	}, {
		want:  assert.True,
		left:  "||example.org$domain=example.org",
		right: "||example.org$script,stylesheet",
	}, {
		want:  assert.True,
		left:  "||example.org$script,stylesheet",
		right: "||example.org$script",
	}, {
		want:  assert.True,
		left:  "||example.org$script,denyallow=com",
		right: "||example.org$client=123",
	}, {
		want:  assert.False,
		left:  "||example.org$client=123",
		right: "||example.org$script,denyallow=com",
	}, {
		want:  assert.True,
		left:  "||example.org$ctag=123,client=123",
		right: "||example.org$script",
	}, {
		want:  assert.True,
		left:  "||example.org$ctag=123,client=123,dnstype=AAAA",
		right: "||example.org$client=123,dnstype=AAAA",
	}, {
		want:  assert.True,
		left:  "||example.org$denyallow=com",
		right: "||example.org",
	}, {
		want:  assert.True,
		left:  "||example.org$client=123,denyallow=com",
		right: "||example.org$script",
	}, {
		want:  assert.False,
		left:  "||example.org$script",
		right: "||example.org$client=123,denyallow=com",
	}, {
		want:  assert.True,
		left:  "||example.org$respgeo=FR",
		right: "||example.org",
	}, {
		want:  assert.True,
		left:  "||example.org$respgeo=~",
		right: "||example.org",
	}}

	for _, tc := range testCases {
		t.Run(tc.left+"-"+tc.right, func(t *testing.T) {
			t.Parallel()

			l := uftest.NewNetworkRule(t, tc.left)
			r := uftest.NewNetworkRule(t, tc.right)
			tc.want(t, l.IsHigherPriority(r))
		})
	}
}

func TestNetworkRule_Match_source(t *testing.T) {
	t.Parallel()

	urlStr := "https://ci.phncdn.com/videos/201809/25/184777011/original/" +
		"(m=ecuKGgaaaa)(mh=VSmV9NL_iouBcWJJ)4.jpg"
	sourceURLStr := "https://www.pornhub.com/view_video.php?viewkey=ph5be89d11de4b0"

	req := rules.NewRequest(urlStr, sourceURLStr, rules.TypeImage)
	ruleText := "|https://$image,media,script,third-party,domain=" +
		"~feedback.pornhub.com|pornhub.com|redtube.com|redtube.com.br|tube8.com|" +
		"tube8.es|tube8.fr|youporn.com|youporngay.com"

	r := uftest.NewNetworkRule(t, ruleText)
	assert.True(t, r.Match(req))
}

func TestNetworkRule_invalidRule(t *testing.T) {
	t.Parallel()

	r, err := rules.NewNetworkRule("*$third-party", uftest.ListID1)
	assert.Nil(t, r)
	assert.ErrorIs(t, err, rules.ErrTooWideRule)

	r, err = rules.NewNetworkRule("$third-party", uftest.ListID1)
	assert.Nil(t, r)
	assert.ErrorIs(t, err, rules.ErrTooWideRule)

	r, err = rules.NewNetworkRule("ad$third-party", uftest.ListID1)
	assert.Nil(t, r)
	assert.ErrorIs(t, err, rules.ErrTooWideRule)

	// This one is valid because it has domain restriction.
	r, err = rules.NewNetworkRule("$domain=ya.ru", uftest.ListID1)
	require.NoError(t, err)
	assert.NotNil(t, r)

	// This one is valid because it has $ctag restriction.
	r, err = rules.NewNetworkRule("$ctag=pc", uftest.ListID1)
	require.NoError(t, err)
	assert.NotNil(t, r)

	// This one is valid because it has $client restriction.
	r, err = rules.NewNetworkRule("$client=127.0.0.1", uftest.ListID1)
	require.NoError(t, err)
	assert.NotNil(t, r)

	// This one is valid because it has $client restriction.
	r, err = rules.NewNetworkRule("/$client=127.0.0.1", uftest.ListID1)
	require.NoError(t, err)
	require.NotNil(t, r)

	req := rules.NewRequest(uftest.URLStrHost, "", rules.TypeOther)
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

			r := uftest.NewNetworkRule(t, tc.ruleText)
			tc.want(t, r.IsHostLevelNetworkRule())
		})
	}
}

func TestNetworkRule_Match_ip(t *testing.T) {
	t.Parallel()

	r := uftest.NewNetworkRule(t, "://104.154.")
	require.True(t, r.IsHostLevelNetworkRule())

	req := rules.NewRequestForHostname("104.154.1.1")
	assert.True(t, r.Match(req))

	req = rules.NewRequestForHostname("1.104.154.1")
	assert.False(t, r.Match(req))
}

func TestNetworkRule_agh1950(t *testing.T) {
	t.Parallel()

	r := uftest.NewNetworkRule(t, "/sub.")
	req := rules.NewRequestForHostname("sub.example.org")
	assert.True(t, r.Match(req))

	req = rules.NewRequestForHostname("sub.host.org")
	assert.True(t, r.Match(req))

	req = rules.NewRequestForHostname("sub2.host.org")
	assert.False(t, r.Match(req))

	req = rules.NewRequestForHostname("2sub.host.org")
	assert.False(t, r.Match(req))
}

func TestNetworkRule_Match_dnsType(t *testing.T) {
	t.Parallel()

	req := rules.NewRequestForHostname(uftest.Host)
	req.DNSType = dns.TypeAAAA

	r := uftest.NewNetworkRule(t, uftest.RuleHost+"$dnstype=TXT|AAAA")
	assert.True(t, r.Match(req))

	r = uftest.NewNetworkRule(t, uftest.RuleHost+"$dnstype=~TXT|~AAAA")
	assert.False(t, r.Match(req))

	r = uftest.NewNetworkRule(t, "$dnstype=AAAA")
	assert.True(t, r.Match(req))

	t.Run("parse_errors", func(t *testing.T) {
		_, err := rules.NewNetworkRule("||error.example^$dnstype=", uftest.ListID1)
		assert.Error(t, err)

		_, err = rules.NewNetworkRule("||error.example^$dnstype=TXT|", uftest.ListID1)
		assert.Error(t, err)

		_, err = rules.NewNetworkRule("||error.example^$dnstype=NONE", uftest.ListID1)
		assert.Error(t, err)

		_, err = rules.NewNetworkRule("||error.example^$dnstype=INVALIDTYPE", uftest.ListID1)
		assert.Error(t, err)
	})
}

func BenchmarkNetworkRule_Match(b *testing.B) {
	r := uftest.NewNetworkRule(b, "||example.org^")
	req := rules.NewRequestForHostname("example.org")

	// Warmup to make sure the init has run.
	ok := r.Match(req)
	require.True(b, ok)

	b.ReportAllocs()
	for b.Loop() {
		ok = r.Match(req)
	}

	require.True(b, ok)

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/urlfilter/rules
	//	cpu: Apple M3
	//	BenchmarkNetworkRule_Match-8   	 3261547	       359.4 ns/op	       0 B/op	       0 allocs/op
}

// TODO(d.kolyshev): Improve this benchmark.
func BenchmarkNetworkRule_IsHigherPriority(b *testing.B) {
	l := uftest.NewNetworkRule(b, "||example.org$ctag=123,client=123,dnstype=AAAA")
	r := uftest.NewNetworkRule(b, "||example.org$client=123,dnstype=AAAA")

	var ok bool
	b.ReportAllocs()
	for b.Loop() {
		ok = l.IsHigherPriority(r)
	}

	require.True(b, ok)

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/urlfilter/rules
	//	cpu: Apple M1 Pro
	//	BenchmarkNetworkRule_IsHigherPriority-8   	134632681	         8.891 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkNetworkRule_Match_Tags(b *testing.B) {
	r := uftest.NewNetworkRule(b, "||example.org^$ctag=device_pc|~device_phone")
	req := rules.NewRequestForHostname("example.org")
	req.ClientTags = container.NewSortedSliceSet("device_pc", "os_macos", "user_child")

	var ok bool

	b.ReportAllocs()
	for b.Loop() {
		ok = r.Match(req)
	}

	require.True(b, ok)

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/urlfilter/rules
	//	cpu: Apple M3
	//	BenchmarkNetworkRule_Match_Tags-8   	 3062398	       378.5 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkNetworkRule_Match_ClientIdentifiers(b *testing.B) {
	r := uftest.NewNetworkRule(b, "||example.org^$client=id_1|id_2|id_3|id_4|id_5|id_6")
	req := rules.NewRequestForHostname("example.org")
	req.ClientIdentifiers = container.NewSortedSliceSet("id_5")

	var ok bool

	b.ReportAllocs()
	for b.Loop() {
		ok = r.Match(req)
	}

	require.True(b, ok)

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/urlfilter/rules
	//	cpu: Apple M3
	//	BenchmarkNetworkRule_Match_ClientIdentifiers-8   	 3014610	       390.0 ns/op	       0 B/op	       0 allocs/op
}

func FuzzNetworkRule_Match(f *testing.F) {
	r := uftest.NewNetworkRule(f, "||test.example^")

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

func FuzzNewNetworkRule(f *testing.F) {
	for _, seed := range []string{
		"",
		" ",
		"1",
		"^",
		"$client=127.0.0.1",
		"^$client=1",
		"@@||example.org$document,~extension",
		"||github.com^",
		"*$third-party",
		"$dnstype=",
		"/regex/",
		"$unknown=value",
		"||example.org$domain=|",
		"example.org$",
	} {
		f.Add(seed)
	}

	req := rules.NewRequestForHostname(uftest.Host)
	req.ClientIP = netutil.IPv4Localhost()

	f.Fuzz(func(t *testing.T, rule string) {
		assert.NotPanics(t, func() {
			r, err := rules.NewNetworkRule(rule, uftest.ListID1)
			if err != nil {
				return
			}

			r.Match(req)
		})
	})
}
