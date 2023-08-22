package rules

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkRule_ParseRuleText(t *testing.T) {
	testCases := []struct {
		wantWhitelist assert.BoolAssertionFunc
		name          string
		in            string
		wantPattern   string
		wantOptions   string
	}{{
		wantWhitelist: assert.False,
		name:          "url",
		in:            "||example.org^",
		wantPattern:   "||example.org^",
		wantOptions:   "",
	}, {
		wantWhitelist: assert.False,
		name:          "url_with_options",
		in:            "||example.org^$third-party",
		wantPattern:   "||example.org^",
		wantOptions:   "third-party",
	}, {
		wantWhitelist: assert.True,
		name:          "whitelist_url_with_options",
		in:            "@@||example.org^$third-party",
		wantPattern:   "||example.org^",
		wantOptions:   "third-party",
	}, {
		wantWhitelist: assert.False,
		name:          "path_with_options",
		in:            "||example.org/this$is$path$third-party",
		wantPattern:   "||example.org/this$is$path",
		wantOptions:   "third-party",
	}, {
		wantWhitelist: assert.True,
		name:          "whitelist_path_with_options",
		in:            "@@||example.org/this$is$path$third-party",
		wantPattern:   "||example.org/this$is$path",
		wantOptions:   "third-party",
	}, {
		wantWhitelist: assert.False,
		name:          "regex",
		in:            "/regex/",
		wantPattern:   "/regex/",
		wantOptions:   "",
	}, {
		wantWhitelist: assert.True,
		name:          "whitelist_regex",
		in:            "@@/regex/",
		wantPattern:   "/regex/",
		wantOptions:   "",
	}, {
		wantWhitelist: assert.False,
		name:          "regex_with_options",
		in:            "/regex/$replace=/test/test2/",
		wantPattern:   "/regex/",
		wantOptions:   "replace=/test/test2/",
	}, {
		wantWhitelist: assert.True,
		name:          "whitelist_regex_with_options",
		in:            "@@/regex/$replace=/test/test2/",
		wantPattern:   "/regex/",
		wantOptions:   "replace=/test/test2/",
	}, {
		wantWhitelist: assert.False,
		name:          "empty_regex",
		in:            "//",
		wantPattern:   "//",
		wantOptions:   "",
	}, {
		wantWhitelist: assert.False,
		name:          "single_slash",
		in:            "/",
		wantPattern:   "/",
		wantOptions:   "",
	}, {
		wantWhitelist: assert.False,
		name:          "escaped_dollar",
		in:            "||example.org^$client='\\$-client'",
		wantPattern:   "||example.org^",
		wantOptions:   "client='$-client'",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pattern, options, whitelist, err := parseRuleText(tc.in)
			require.NoError(t, err)

			assert.Equal(t, tc.wantPattern, pattern)
			assert.Equal(t, tc.wantOptions, options)
			tc.wantWhitelist(t, whitelist)
		})
	}

	t.Run("bad_rule", func(t *testing.T) {
		_, _, _, err := parseRuleText("@@")
		testutil.AssertErrorMsg(t, "the rule @@ is too short", err)
	})
}

func TestNetworkRule_ParseModifiers(t *testing.T) {
	testCases := []struct {
		name        string
		option      NetworkRuleOption
		wantEnabled bool
	}{{
		name:        "important",
		option:      OptionImportant,
		wantEnabled: true,
	}, {
		name:        "third-party",
		option:      OptionThirdParty,
		wantEnabled: true,
	}, {
		name:        "~first-party",
		option:      OptionThirdParty,
		wantEnabled: true,
	}, {
		name:        "first-party",
		option:      OptionThirdParty,
		wantEnabled: false,
	}, {
		name:        "~third-party",
		option:      OptionThirdParty,
		wantEnabled: false,
	}, {
		name:        "match-case",
		option:      OptionMatchCase,
		wantEnabled: true,
	}, {
		name:        "~match-case",
		option:      OptionMatchCase,
		wantEnabled: false,
	}, {
		name:        "elemhide",
		option:      OptionElemhide,
		wantEnabled: true,
	}, {
		name:        "generichide",
		option:      OptionGenerichide,
		wantEnabled: true,
	}, {
		name:        "genericblock",
		option:      OptionGenericblock,
		wantEnabled: true,
	}, {
		name:        "jsinject",
		option:      OptionJsinject,
		wantEnabled: true,
	}, {
		name:        "urlblock",
		option:      OptionUrlblock,
		wantEnabled: true,
	}, {
		name:        "content",
		option:      OptionContent,
		wantEnabled: true,
	}, {
		name:        "extension",
		option:      OptionExtension,
		wantEnabled: true,
	}, {
		name:        "document",
		option:      OptionElemhide,
		wantEnabled: true,
	}, {
		name:        "document",
		option:      OptionJsinject,
		wantEnabled: true,
	}, {
		name:        "document",
		option:      OptionUrlblock,
		wantEnabled: true,
	}, {
		name:        "document",
		option:      OptionContent,
		wantEnabled: true,
	}, {
		name:        "document",
		option:      OptionExtension,
		wantEnabled: true,
	}, {
		name:        "stealth",
		option:      OptionStealth,
		wantEnabled: true,
	}, {
		name:        "popup",
		option:      OptionPopup,
		wantEnabled: true,
	}, {
		name:        "empty",
		option:      OptionEmpty,
		wantEnabled: true,
	}, {
		name:        "mp4",
		option:      OptionMp4,
		wantEnabled: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var ruleText string
			if (tc.option & OptionWhitelistOnly) != 0 {
				ruleText = "@@"
			}
			ruleText += "||example.org$" + tc.name

			f, err := NewNetworkRule(ruleText, 0)
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

func TestNetworkRule_CountModifiers(t *testing.T) {
	for _, tc := range []struct {
		option  NetworkRuleOption
		wantNum int
	}{{
		option:  OptionImportant,
		wantNum: 1,
	}, {
		option:  OptionImportant | OptionStealth,
		wantNum: 2,
	}, {
		option:  OptionImportant | OptionStealth | OptionRedirect | OptionUrlblock,
		wantNum: 4,
	}, {
		option:  0,
		wantNum: 0,
	}} {
		assert.Equal(t, tc.option.Count(), tc.wantNum)
	}
}

func TestNetworkRule_DisablingExtensionModifier(t *testing.T) {
	ruleText := "@@||example.org$document,~extension"

	f, err := NewNetworkRule(ruleText, 0)
	assert.Nil(t, err)
	assert.NotNil(t, f)
	assert.False(t, f.IsOptionEnabled(OptionExtension))
	assert.False(t, f.IsOptionDisabled(OptionExtension))
}

func checkRequestType(t *testing.T, name string, requestType RequestType, permitted bool) {
	f, err := NewNetworkRule("||example.org^$"+name, 0)
	assert.Nil(t, err)
	assert.NotNil(t, f)

	if permitted {
		assert.Equal(t, f.permittedRequestTypes, requestType)
	} else {
		assert.Equal(t, f.restrictedRequestTypes, requestType)
	}
}

func TestNetworkRule_ParseRequestTypeModifiers(t *testing.T) {
	checkRequestType(t, "script", TypeScript, true)
	checkRequestType(t, "~script", TypeScript, false)

	checkRequestType(t, "stylesheet", TypeStylesheet, true)
	checkRequestType(t, "~stylesheet", TypeStylesheet, false)

	checkRequestType(t, "subdocument", TypeSubdocument, true)
	checkRequestType(t, "~subdocument", TypeSubdocument, false)

	checkRequestType(t, "object", TypeObject, true)
	checkRequestType(t, "~object", TypeObject, false)

	checkRequestType(t, "object", TypeObject, true)
	checkRequestType(t, "~object", TypeObject, false)

	checkRequestType(t, "image", TypeImage, true)
	checkRequestType(t, "~image", TypeImage, false)

	checkRequestType(t, "xmlhttprequest", TypeXmlhttprequest, true)
	checkRequestType(t, "~xmlhttprequest", TypeXmlhttprequest, false)

	checkRequestType(t, "media", TypeMedia, true)
	checkRequestType(t, "~media", TypeMedia, false)

	checkRequestType(t, "font", TypeFont, true)
	checkRequestType(t, "~font", TypeFont, false)

	checkRequestType(t, "websocket", TypeWebsocket, true)
	checkRequestType(t, "~websocket", TypeWebsocket, false)

	checkRequestType(t, "ping", TypePing, true)
	checkRequestType(t, "~ping", TypePing, false)

	checkRequestType(t, "other", TypeOther, true)
	checkRequestType(t, "~other", TypeOther, false)
}

func TestNetworkRule_FindShortcut(t *testing.T) {
	shortcut := findShortcut("||example.org^")
	assert.Equal(t, "example.org", shortcut)

	shortcut = findShortcut("|https://*examp")
	assert.Equal(t, "https://", shortcut)

	shortcut = findRegexpShortcut("/example/")
	assert.Equal(t, "example", shortcut)

	shortcut = findRegexpShortcut("/^http:\\/\\/example/")
	assert.Equal(t, "/example", shortcut)

	shortcut = findRegexpShortcut("/^http:\\/\\/[a-z]+\\.example/")
	assert.Equal(t, "example", shortcut)

	shortcut = findRegexpShortcut("//")
	assert.Equal(t, "", shortcut)

	shortcut = findRegexpShortcut("/^http:\\/\\/(?!test.)example.org/")
	assert.Equal(t, "", shortcut)
}

func TestNetworkRule_SimpleBasicRules(t *testing.T) {
	// Simple matching rule
	f, err := NewNetworkRule("||example.org^", 0)
	r := NewRequest("https://example.org/", "", TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	f, err = NewNetworkRule("||example.org/*", 0)
	r = NewRequest("https://example.org/", "", TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	// Subdomains / domains
	f, err = NewNetworkRule("||github.com^", 0)
	r = NewRequestForHostname("dualstack.log.github.com-east-1.elb.amazonaws.com")
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	r = NewRequestForHostname("dualstack.log.github.com1-east-1.elb.amazonaws.com")
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	// Simple regex rule
	f, err = NewNetworkRule("/example\\.org/", 0)
	r = NewRequest("https://example.org/", "", TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	// Simple pattern rule
	f, err = NewNetworkRule("_prebid_", 0)
	r = NewRequest("https://ap.lijit.com/rtb/bid?src=prebid_prebid_1.35.0", "https://www.drudgereport.com/", TypeXmlhttprequest)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))
}

func TestNetworkRule_InvalidModifiers(t *testing.T) {
	_, err := NewNetworkRule("||example.org^$unknown", 0)
	assert.NotNil(t, err)

	// Whitelist-only modifier
	_, err = NewNetworkRule("||example.org^$elemhide", 0)
	assert.NotNil(t, err)

	// Blacklist-only modifier
	_, err = NewNetworkRule("@@||example.org^$popup", 0)
	assert.NotNil(t, err)
}

func TestNetworkRule_MatchCase(t *testing.T) {
	f, err := NewNetworkRule("||example.org^$match-case", 0)
	r := NewRequest("https://example.org/", "", TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = NewRequest("https://EXAMPLE.org/", "", TypeOther)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))
}

func TestNetworkRule_ThirdParty(t *testing.T) {
	f, err := NewNetworkRule("||example.org^$third-party", 0)

	// First-party 1
	r := NewRequest("https://example.org/", "", TypeOther)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	// First-party 2
	r = NewRequest("https://sub.example.org/", "https://example.org/", TypeOther)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	// Third-party
	r = NewRequest("https://example.org/", "https://example.com", TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	f, err = NewNetworkRule("||example.org^$first-party", 0)

	// First-party 1
	r = NewRequest("https://example.org/", "", TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	// First-party
	r = NewRequest("https://sub.example.org/", "https://example.org/", TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	// Third-party
	r = NewRequest("https://example.org/", "https://example.com", TypeOther)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))
}

func TestNetworkRule_ContentType(t *testing.T) {
	// $script
	f, err := NewNetworkRule("||example.org^$script", 0)
	r := NewRequest("https://example.org/", "", TypeScript)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = NewRequest("https://example.org/", "", TypeDocument)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	// $script and $stylesheet
	f, err = NewNetworkRule("||example.org^$script,stylesheet", 0)
	r = NewRequest("https://example.org/", "", TypeScript)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = NewRequest("https://example.org/", "", TypeStylesheet)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = NewRequest("https://example.org/", "", TypeDocument)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	// Everything except $script and $stylesheet
	f, err = NewNetworkRule("@@||example.org^$~script,~stylesheet", 0)
	r = NewRequest("https://example.org/", "", TypeScript)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	r = NewRequest("https://example.org/", "", TypeStylesheet)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	r = NewRequest("https://example.org/", "", TypeDocument)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))
}

func TestNetworkRule_DomainRestrictions(t *testing.T) {
	// Just one permitted domain
	f, err := NewNetworkRule("||example.org^$domain=example.org", 0)
	r := NewRequest("https://example.org/", "", TypeScript)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	r = NewRequest("https://example.org/", "https://example.org/", TypeScript)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = NewRequest("https://example.org/", "https://subdomain.example.org/", TypeScript)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	// One permitted, subdomain restricted
	f, err = NewNetworkRule("||example.org^$domain=example.org|~subdomain.example.org", 0)
	r = NewRequest("https://example.org/", "", TypeScript)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	r = NewRequest("https://example.org/", "https://example.org/", TypeScript)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = NewRequest("https://example.org/", "https://subdomain.example.org/", TypeScript)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	// One restricted
	f, err = NewNetworkRule("||example.org^$domain=~example.org", 0)
	r = NewRequest("https://example.org/", "", TypeScript)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = NewRequest("https://example.org/", "https://example.org/", TypeScript)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	r = NewRequest("https://example.org/", "https://subdomain.example.org/", TypeScript)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	// Wide restricted
	f, err = NewNetworkRule("$domain=example.org", 0)
	r = NewRequest("https://example.com/", "https://example.org/", TypeScript)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))
}

func TestNetworkRule_Denyallow(t *testing.T) {
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
			f, err := NewNetworkRule(tc.ruleText, 0)
			if tc.fail {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			r := NewRequest(tc.requestURL, tc.sourceURL, TypeScript)
			r.IsHostnameRequest = tc.requestForHostname
			require.Equal(t, tc.match, f.Match(r))
		})
	}
}

func TestNetworkRule_WildcardTLDRestrictions(t *testing.T) {
	f, err := NewNetworkRule("||example.org^$domain=example.*", 0)
	assert.Nil(t, err)

	r := NewRequest("https://example.org/", "", TypeScript)
	assert.False(t, f.Match(r))

	r = NewRequest("https://example.org/", "https://example.com/", TypeScript)
	assert.True(t, f.Match(r))

	r = NewRequest("https://example.org/", "https://example.co.uk/", TypeScript)
	assert.True(t, f.Match(r))

	r = NewRequest("https://example.org/", "https://test.example.co.uk/", TypeScript)
	assert.True(t, f.Match(r))

	// Not a public suffix
	r = NewRequest("https://example.org/", "https://example.local/", TypeScript)
	assert.False(t, f.Match(r))

	// Not a public suffix
	r = NewRequest("https://example.org/", "https://example.test.test/", TypeScript)
	assert.False(t, f.Match(r))
}

func TestNetworkRule_InvalidDomainRestrictions(t *testing.T) {
	_, err := NewNetworkRule("||example.org^$domain=", 0)
	assert.NotNil(t, err)

	_, err = NewNetworkRule("||example.org^$domain=|example.com", 0)
	assert.NotNil(t, err)
}

func TestNetworkRule_LoadCTags(t *testing.T) {
	perm, rest, err := loadCTags("phone|pc|~printer", "|")
	assert.Nil(t, err)
	assert.Equal(t, []string{"pc", "phone"}, perm)
	assert.Equal(t, []string{"printer"}, rest)

	perm, rest, err = loadCTags("device_pc0123", "|")
	assert.Nil(t, err)
	assert.Equal(t, []string{"device_pc0123"}, perm)
	assert.Nil(t, rest)

	perm, rest, err = loadCTags("pc|~phone|bad.", "|")
	assert.NotNil(t, err)
	assert.Equal(t, []string{"pc"}, perm)
	assert.Equal(t, []string{"phone"}, rest)
}

func TestNetworkRule_ClientTagRules(t *testing.T) {
	f, err := NewNetworkRule("||example.org^$ctag=pc", 0)
	assert.Nil(t, err)
	assert.NotNil(t, f)
	assert.Equal(t, []string{"pc"}, f.permittedClientTags)

	r := NewRequestForHostname("example.org")
	r.SortedClientTags = []string{"pc"}
	assert.True(t, f.Match(r))

	r.SortedClientTags = nil
	assert.False(t, f.Match(r))

	f, _ = NewNetworkRule("||example.org^$ctag=phone|pc", 0)
	assert.Equal(t, []string{"pc", "phone"}, f.permittedClientTags)

	r.SortedClientTags = []string{"phone", "other"}
	assert.True(t, f.Match(r))

	r.SortedClientTags = nil
	assert.False(t, f.Match(r))

	f, _ = NewNetworkRule("||example.org^$ctag=~phone|pc", 0)
	assert.Equal(t, []string{"pc"}, f.permittedClientTags)
	assert.Equal(t, []string{"phone"}, f.restrictedClientTags)

	r.SortedClientTags = []string{"phone", "pc"}
	assert.False(t, f.Match(r))

	r.SortedClientTags = []string{"pc"}
	assert.True(t, f.Match(r))

	r.SortedClientTags = []string{"phone"}
	assert.False(t, f.Match(r))
}

func TestNetworkRule_LoadClients(t *testing.T) {
	p, r, err := loadClients("127.0.0.1", '|')
	assert.Nil(t, err)
	assert.Equal(t, *newClients("127.0.0.1"), *p)
	assert.Nil(t, r)

	p, r, err = loadClients("127.0.0.1|127.0.0.2", '|')
	assert.Nil(t, err)
	assert.Equal(t, *newClients("127.0.0.1", "127.0.0.2"), *p)
	assert.Nil(t, r)

	p, r, err = loadClients("127.0.0.1|~127.0.0.2", '|')
	assert.Nil(t, err)
	assert.Equal(t, *newClients("127.0.0.1"), *p)
	assert.Equal(t, *newClients("127.0.0.2"), *r)

	p, r, err = loadClients("'Frank\\'s laptop'", '|')
	assert.Nil(t, err)
	assert.Equal(t, *newClients("Frank's laptop"), *p)
	assert.Nil(t, r)

	p, r, err = loadClients("~\"Frank's phone\"", '|')
	assert.Nil(t, err)
	assert.Nil(t, p)
	assert.Equal(t, *newClients("Frank's phone"), *r)

	p, r, err = loadClients("~'Mary\\'s\\, John\\'s\\, and Boris\\'s laptops'", '|')
	assert.Nil(t, err)
	assert.Nil(t, p)
	assert.Equal(t, *newClients("Mary's, John's, and Boris's laptops"), *r)

	p, r, err = loadClients("~Mom|~Dad|\"Kids\"", '|')
	assert.Nil(t, err)
	assert.Equal(t, *newClients("Kids"), *p)
	assert.Equal(t, *newClients("Dad", "Mom"), *r)
}

func TestNetworkRule_LoadInvalidClients(t *testing.T) {
	_, _, err := loadClients("", '|')
	assert.NotNil(t, err)

	_, _, err = loadClients("''", '|')
	assert.NotNil(t, err)

	_, _, err = loadClients("~''", '|')
	assert.NotNil(t, err)

	_, _, err = loadClients("~", '|')
	assert.NotNil(t, err)
}

func TestNetworkRule_MatchClients(t *testing.T) {
	f, err := NewNetworkRule("||example.org^$client=127.0.0.1", 0)
	assert.Nil(t, err)
	assert.NotNil(t, f)

	r := NewRequestForHostname("example.org")
	r.ClientIP = netip.MustParseAddr("127.0.0.1")
	assert.True(t, f.Match(r))

	r.ClientIP = netip.MustParseAddr("127.0.0.2")
	assert.False(t, f.Match(r))

	f, err = NewNetworkRule("||example.org^$client=127.0.0.0/8", 0)
	assert.Nil(t, err)
	assert.NotNil(t, f)

	r.ClientIP = netip.MustParseAddr("127.1.1.1")
	assert.True(t, f.Match(r))

	r.ClientIP = netip.MustParseAddr("126.0.0.0")
	assert.False(t, f.Match(r))

	f, err = NewNetworkRule("||example.org^$client=2001::0:00c0:ffee", 0)
	assert.Nil(t, err)
	assert.NotNil(t, f)

	r.ClientIP = netip.MustParseAddr("2001::c0:ffee")
	assert.True(t, f.Match(r))

	r.ClientIP = netip.MustParseAddr("2001::c0:ffef")
	assert.False(t, f.Match(r))

	f, err = NewNetworkRule("||example.org^$client=2001::0:00c0:ffee/112", 0)
	assert.Nil(t, err)
	assert.NotNil(t, f)

	r.ClientIP = netip.MustParseAddr("2001::0:c0:0")
	assert.True(t, f.Match(r))

	r.ClientIP = netip.MustParseAddr("2001::c1:ffee")
	assert.False(t, f.Match(r))

	f, err = NewNetworkRule("||example.org^$client=~'Frank\\'s laptop'", 0)
	assert.Nil(t, err)
	assert.NotNil(t, f)

	r.ClientName = "Frank's laptop"
	assert.False(t, f.Match(r))

	r.ClientName = "Frank's phone"
	assert.True(t, f.Match(r))

	f, err = NewNetworkRule("||example.org^$client=name", 0)
	assert.Nil(t, err)
	assert.NotNil(t, f)

	r.ClientIP = netip.MustParseAddr("127.0.0.1")
	r.ClientName = "name"
	assert.True(t, f.Match(r))

	r.ClientIP = netip.MustParseAddr("127.0.0.1")
	r.ClientName = "another-name"
	assert.False(t, f.Match(r))
}

func TestNetworkRule_Priority(t *testing.T) {
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

func TestNetworkRule_MatchSource(t *testing.T) {
	url := "https://ci.phncdn.com/videos/201809/25/184777011/original/(m=ecuKGgaaaa)(mh=VSmV9NL_iouBcWJJ)4.jpg"
	sourceURL := "https://www.pornhub.com/view_video.php?viewkey=ph5be89d11de4b0"

	r := NewRequest(url, sourceURL, TypeImage)
	ruleText := "|https://$image,media,script,third-party,domain=~feedback.pornhub.com|pornhub.com|redtube.com|redtube.com.br|tube8.com|tube8.es|tube8.fr|youporn.com|youporngay.com"
	f, err := NewNetworkRule(ruleText, 0)
	if err != nil {
		t.Fatalf("failed to create rule: %s", err)
	}

	assert.True(t, f.Match(r))
}

func TestNetworkRule_InvalidRule(t *testing.T) {
	r, err := NewNetworkRule("*$third-party", -1)
	assert.Nil(t, r)
	assert.Equal(t, ErrTooWideRule, err)

	r, err = NewNetworkRule("$third-party", -1)
	assert.Nil(t, r)
	assert.Equal(t, ErrTooWideRule, err)

	r, err = NewNetworkRule("ad$third-party", -1)
	assert.Nil(t, r)
	assert.Equal(t, ErrTooWideRule, err)

	// This one is valid because it has domain restriction
	r, err = NewNetworkRule("$domain=ya.ru", -1)
	assert.NotNil(t, r)
	assert.Nil(t, err)

	// This one is valid because it has $ctag restriction
	r, err = NewNetworkRule("$ctag=pc", -1)
	assert.NotNil(t, r)
	assert.Nil(t, err)

	// This one is valid because it has $client restriction
	r, err = NewNetworkRule("$client=127.0.0.1", -1)
	assert.NotNil(t, r)
	assert.Nil(t, err)

	// This one is valid because it has $client restriction
	r, err = NewNetworkRule("/$client=127.0.0.1", -1)
	require.NotNil(t, r)
	require.NoError(t, err)

	req := NewRequest("https://example.org/", "", TypeOther)
	req.ClientIP = netip.MustParseAddr("127.0.0.1")
	assert.True(t, r.Match(req))
}

func TestNetworkRule_negatesBadfilter(t *testing.T) {
	testCases := []struct {
		want      assert.BoolAssertionFunc
		name      string
		rule      string
		badfilter string
	}{{
		want:      assert.True,
		name:      "success",
		rule:      "*$image,domain=example.org",
		badfilter: "*$image,domain=example.org,badfilter",
	}, {
		want:      assert.False,
		name:      "no_image",
		rule:      "*$image,domain=example.org",
		badfilter: "*$domain=example.org,badfilter",
	}, {
		want:      assert.True,
		name:      "badfilter_first",
		rule:      "*$image,domain=example.org",
		badfilter: "*$image,badfilter,domain=example.org",
	}, {
		want:      assert.False,
		name:      "several_domains",
		rule:      "*$image,domain=example.org|example.com",
		badfilter: "*$image,domain=example.org,badfilter",
	}, {
		want:      assert.True,
		name:      "whitelist_success",
		rule:      "@@*$image,domain=example.org",
		badfilter: "@@*$image,domain=example.org,badfilter",
	}, {
		want:      assert.False,
		name:      "whitelist_over_badfilter",
		rule:      "@@*$image,domain=example.org",
		badfilter: "*$image,domain=example.org,badfilter",
	}, {
		want:      assert.False,
		name:      "different_ctags",
		rule:      "*$ctag=phone",
		badfilter: "*$ctag=pc,badfilter",
	}, {
		want:      assert.True,
		name:      "different_ctags_order",
		rule:      "*$ctag=phone|pc",
		badfilter: "*$ctag=pc|phone,badfilter",
	}, {
		want:      assert.False,
		name:      "different_clients",
		rule:      "*$client=127.0.0.1",
		badfilter: "*$client=127.0.0.2,badfilter",
	}, {
		want:      assert.True,
		name:      "same_clients",
		rule:      "*$client=127.0.0.1",
		badfilter: "*$client=127.0.0.1,badfilter",
	}, {
		want:      assert.True,
		name:      "different_clients_order",
		rule:      "*$client=::|127.0.0.1",
		badfilter: "*$client=127.0.0.1|::,badfilter",
	}, {
		want:      assert.True,
		name:      "different_client_subnets_order",
		rule:      "*$client=127.0.0.1/8|10.0.0.0/8",
		badfilter: "*$client=10.0.0.0/8|127.0.0.1/8,badfilter",
	}, {
		want:      assert.True,
		name:      "different_client_subnets",
		rule:      "*$client=::",
		badfilter: "*$client=0:0000::0,badfilter",
	}, {
		want:      assert.True,
		name:      "different_ipv4_subnets_order",
		rule:      "*$client=127.0.0.1/24|127.0.0.1/16",
		badfilter: "*$client=127.0.0.1/16|127.0.0.1/24,badfilter",
	}, {
		want:      assert.True,
		name:      "different_mixed_subnets_order",
		rule:      "*$client=fe01::/16|127.0.0.1|1::/16",
		badfilter: "*$client=127.0.0.1|1::/16|fe01::/16,badfilter",
	}, {
		want:      assert.False,
		name:      "different_ipv6_subnets_length",
		rule:      "*$client=::/64",
		badfilter: "*$client=::/63,badfilter",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewNetworkRule(tc.rule, -1)
			require.NoError(t, err)
			require.NotNil(t, r)

			b, err := NewNetworkRule(tc.badfilter, -1)
			require.NoError(t, err)
			require.NotNil(t, b)

			tc.want(t, b.negatesBadfilter(r))
		})
	}
}

func TestNetworkRule_IsHostLevelNetworkRule(t *testing.T) {
	r, err := NewNetworkRule("||example.org^$important", -1)
	assert.Nil(t, err)
	assert.True(t, r.IsHostLevelNetworkRule())

	r, err = NewNetworkRule("||example.org^$important,badfilter", -1)
	assert.Nil(t, err)
	assert.True(t, r.IsHostLevelNetworkRule())

	r, err = NewNetworkRule("||example.org^$badfilter", -1)
	assert.Nil(t, err)
	assert.True(t, r.IsHostLevelNetworkRule())

	r, err = NewNetworkRule("||example.org^", -1)
	assert.Nil(t, err)
	assert.True(t, r.IsHostLevelNetworkRule())

	r, err = NewNetworkRule("||example.org^$~third-party", -1)
	assert.Nil(t, err)
	assert.False(t, r.IsHostLevelNetworkRule())

	r, err = NewNetworkRule("||example.org^$third-party", -1)
	assert.Nil(t, err)
	assert.False(t, r.IsHostLevelNetworkRule())

	r, err = NewNetworkRule("||example.org^$domain=example.com", -1)
	assert.Nil(t, err)
	assert.False(t, r.IsHostLevelNetworkRule())
}

func TestNetworkRule_MatchIPAddress(t *testing.T) {
	f, err := NewNetworkRule("://104.154.", -1)
	assert.Nil(t, err)
	assert.True(t, f.IsHostLevelNetworkRule())

	r := NewRequestForHostname("104.154.1.1")
	assert.True(t, f.Match(r))

	r = NewRequestForHostname("1.104.154.1")
	assert.False(t, f.Match(r))

	f, err = NewNetworkRule("/sub.", 0)
	assert.Nil(t, err)
	r = NewRequestForHostname("sub.example.org")
	assert.True(t, f.Match(r))
	r = NewRequestForHostname("sub.host.org")
	assert.True(t, f.Match(r))
	r = NewRequestForHostname("sub2.host.org")
	assert.False(t, f.Match(r))
	r = NewRequestForHostname("2sub.host.org")
	assert.False(t, f.Match(r))
}

func compareRulesPriority(t *testing.T, left, right string, expected bool) {
	l, err := NewNetworkRule(left, -1)
	assert.Nil(t, err)
	r, err := NewNetworkRule(right, -1)
	assert.Nil(t, err)
	assert.Equal(t, expected, l.IsHigherPriority(r))
}

func TestNetworkRule_Match_dnsType(t *testing.T) {
	req := NewRequestForHostname("example.org")
	req.DNSType = dns.TypeAAAA

	r, err := NewNetworkRule("||example.org^$dnstype=TXT|AAAA", -1)
	assert.Nil(t, err)
	assert.True(t, r.Match(req))

	r, err = NewNetworkRule("||example.org^$dnstype=~TXT|~AAAA", -1)
	assert.Nil(t, err)
	assert.False(t, r.Match(req))

	r, err = NewNetworkRule("$dnstype=AAAA", -1)
	assert.Nil(t, err)
	assert.True(t, r.Match(req))

	t.Run("parse_errors", func(t *testing.T) {
		_, err = NewNetworkRule("||example.org^$dnstype=", -1)
		assert.NotNil(t, err)

		_, err = NewNetworkRule("||example.org^$dnstype=TXT|", -1)
		assert.NotNil(t, err)

		_, err = NewNetworkRule("||example.org^$dnstype=NONE", -1)
		assert.NotNil(t, err)

		_, err = NewNetworkRule("||example.org^$dnstype=INVALIDTYPE", -1)
		assert.NotNil(t, err)
	})
}
