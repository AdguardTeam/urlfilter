package rules

import (
	"net/url"
	"testing"

	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRuleText(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

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
func checkRequestType(t testing.TB, modifier string, requestType RequestType, permitted bool) {
	t.Helper()

	r, err := NewNetworkRule("||example.org^$"+modifier, 0)
	require.Nil(t, err)
	require.NotNil(t, r)

	if permitted {
		assert.Equal(t, r.permittedRequestTypes, requestType)
		assert.Equal(t, r.restrictedRequestTypes, RequestType(0))
	} else {
		assert.Equal(t, r.permittedRequestTypes, RequestType(0))
		assert.Equal(t, r.restrictedRequestTypes, requestType)
	}
}

func TestNetworkRule_requestTypeModifiers(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		modifier      string
		want          RequestType
		wantPermitted bool
	}{{
		modifier:      "script",
		want:          TypeScript,
		wantPermitted: true,
	}, {
		modifier:      "stylesheet",
		want:          TypeStylesheet,
		wantPermitted: true,
	}, {
		modifier:      "subdocument",
		want:          TypeSubdocument,
		wantPermitted: true,
	}, {
		modifier:      "object",
		want:          TypeObject,
		wantPermitted: true,
	}, {
		modifier:      "image",
		want:          TypeImage,
		wantPermitted: true,
	}, {
		modifier:      "xmlhttprequest",
		want:          TypeXmlhttprequest,
		wantPermitted: true,
	}, {
		modifier:      "media",
		want:          TypeMedia,
		wantPermitted: true,
	}, {
		modifier:      "font",
		want:          TypeFont,
		wantPermitted: true,
	}, {
		modifier:      "websocket",
		want:          TypeWebsocket,
		wantPermitted: true,
	}, {
		modifier:      "ping",
		want:          TypePing,
		wantPermitted: true,
	}, {
		modifier:      "other",
		want:          TypeOther,
		wantPermitted: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.modifier, func(t *testing.T) {
			t.Parallel()

			checkRequestType(t, tc.modifier, tc.want, true)
			checkRequestType(t, "~"+tc.modifier, tc.want, false)
		})
	}
}

func TestFindShortcut(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		input        string
		wantShortcut string
	}{{
		input:        "||example.org^",
		wantShortcut: "example.org",
	}, {
		input:        "|https://*examp",
		wantShortcut: "https://",
	}}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.wantShortcut, findShortcut(tc.input))
		})
	}
}

func TestFindRegexShortcut(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		input        string
		wantShortcut string
	}{{
		input:        "/example/",
		wantShortcut: "example",
	}, {
		input:        "/^http:\\/\\/example/",
		wantShortcut: "/example",
	}, {
		input:        "/^http:\\/\\/[a-z]+\\.example/",
		wantShortcut: "example",
	}, {
		input:        "//",
		wantShortcut: "",
	}, {
		input:        "/^http:\\/\\/(?!test.)example.org/",
		wantShortcut: "",
	}}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.wantShortcut, findRegexpShortcut(tc.input))
		})
	}
}

func TestParseCTags(t *testing.T) {
	t.Parallel()

	perm, rest, err := parseCTags("phone|pc|~printer", "|")
	require.NoError(t, err)
	assert.Equal(t, []string{"pc", "phone"}, perm)
	assert.Equal(t, []string{"printer"}, rest)

	perm, rest, err = parseCTags("device_pc0123", "|")
	require.NoError(t, err)
	assert.Equal(t, []string{"device_pc0123"}, perm)
	assert.Nil(t, rest)

	perm, rest, err = parseCTags("pc|~phone|bad.", "|")
	require.Error(t, err)
	assert.Equal(t, []string{"pc"}, perm)
	assert.Equal(t, []string{"phone"}, rest)
}

func TestNetworkRule_cTagRules(t *testing.T) {
	t.Parallel()

	t.Run("permitted_one", func(t *testing.T) {
		t.Parallel()

		r, err := NewNetworkRule("||test.example^$ctag=pc", 0)
		require.NoError(t, err)
		require.NotNil(t, r)

		assert.Equal(t, []string{"pc"}, r.permittedClientTags)

		req := NewRequestForURL(&url.URL{
			Scheme: urlutil.SchemeHTTP,
			Host:   "test.example",
		})
		req.SortedClientTags = []string{"pc"}
		assert.True(t, r.Match(req))

		req.SortedClientTags = nil
		assert.False(t, r.Match(req))
	})

	t.Run("permitted_list", func(t *testing.T) {
		t.Parallel()

		r, err := NewNetworkRule("||test.example^$ctag=phone|pc", 0)
		require.NoError(t, err)
		assert.Equal(t, []string{"pc", "phone"}, r.permittedClientTags)

		req := NewRequestForURL(&url.URL{
			Scheme: urlutil.SchemeHTTP,
			Host:   "test.example",
		})
		req.SortedClientTags = []string{"phone", "other"}
		assert.True(t, r.Match(req))

		req.SortedClientTags = nil
		assert.False(t, r.Match(req))
	})

	t.Run("permitted_restricted", func(t *testing.T) {
		t.Parallel()

		r, err := NewNetworkRule("||test.example^$ctag=~phone|pc", 0)
		require.NoError(t, err)
		assert.Equal(t, []string{"pc"}, r.permittedClientTags)
		assert.Equal(t, []string{"phone"}, r.restrictedClientTags)

		req := NewRequestForURL(&url.URL{
			Scheme: urlutil.SchemeHTTP,
			Host:   "test.example",
		})
		req.SortedClientTags = []string{"phone", "pc"}
		assert.False(t, r.Match(req))

		req.SortedClientTags = []string{"pc"}
		assert.True(t, r.Match(req))

		req.SortedClientTags = []string{"phone"}
		assert.False(t, r.Match(req))
	})
}

func TestParseClients(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		wantClients    *clients
		wantRestricted *clients
		input          string
	}{{
		wantClients:    newClients("127.0.0.1"),
		wantRestricted: nil,
		input:          "127.0.0.1",
	}, {
		wantClients:    newClients("127.0.0.1", "127.0.0.2"),
		wantRestricted: nil,
		input:          "127.0.0.1|127.0.0.2",
	}, {
		wantClients:    newClients("127.0.0.1"),
		wantRestricted: newClients("127.0.0.2"),
		input:          "127.0.0.1|~127.0.0.2",
	}, {
		wantClients:    newClients("Frank's laptop"),
		wantRestricted: nil,
		input:          "'Frank\\'s laptop'",
	}, {
		wantClients:    nil,
		wantRestricted: newClients("Frank's phone"),
		input:          "~\"Frank's phone\"",
	}, {
		wantClients:    newClients("Frank's laptop"),
		wantRestricted: newClients("Frank's phone"),
		input:          "~\"Frank's phone\"|'Frank\\'s laptop'",
	}, {
		wantClients:    nil,
		wantRestricted: newClients("Mary's, John's, and Boris's laptops"),
		input:          "~'Mary\\'s\\, John\\'s\\, and Boris\\'s laptops'",
	}, {
		wantClients:    newClients("Kids"),
		wantRestricted: newClients("Dad", "Mom"),
		input:          "~Mom|~Dad|\"Kids\"",
	}}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()

			p, r, err := parseClients(tc.input, '|')
			require.NoError(t, err)

			assert.Equal(t, tc.wantClients, p)
			assert.Equal(t, tc.wantRestricted, r)
		})
	}
}

func TestParseClients_invalid(t *testing.T) {
	t.Parallel()

	_, _, err := parseClients("", '|')
	assert.Error(t, err)

	_, _, err = parseClients("''", '|')
	assert.Error(t, err)

	_, _, err = parseClients("~''", '|')
	assert.Error(t, err)

	_, _, err = parseClients("~", '|')
	assert.Error(t, err)
}

func TestNetworkRule_negatesBadfilter(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

			r, err := NewNetworkRule(tc.rule, testListID)
			require.NoError(t, err)
			require.NotNil(t, r)

			b, err := NewNetworkRule(tc.badfilter, testListID)
			require.NoError(t, err)
			require.NotNil(t, b)

			tc.want(t, b.negatesBadfilter(r))
		})
	}
}
