package rules

import (
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRuleText(t *testing.T) {
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

// checkRequestType creates a new NetworkRule and checks that the request type
// is set correctly.
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

func TestNetworkRule_requestTypeModifiers(t *testing.T) {
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

func TestFindShortcut(t *testing.T) {
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

func TestLoadCTags(t *testing.T) {
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

func TestNetworkRule_clientTagRules(t *testing.T) {
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

func TestLoadClients(t *testing.T) {
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

func TestLoadInvalidClients(t *testing.T) {
	_, _, err := loadClients("", '|')
	assert.NotNil(t, err)

	_, _, err = loadClients("''", '|')
	assert.NotNil(t, err)

	_, _, err = loadClients("~''", '|')
	assert.NotNil(t, err)

	_, _, err = loadClients("~", '|')
	assert.NotNil(t, err)
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
