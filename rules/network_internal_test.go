package rules

import (
	"testing"

	"github.com/AdguardTeam/golibs/container"
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
		testutil.AssertErrorMsg(t, `rule "@@" is too short`, err)
	})

	t.Run("single_circumflex_with_modifier", func(t *testing.T) {
		_, _, _, err := parseRuleText("^$client=1")
		require.NoError(t, err)
	})
}

// checkRequestType creates a new NetworkRule and checks that the request type
// is set correctly.
func checkRequestType(t testing.TB, modifier string, requestType RequestType, permitted bool) {
	t.Helper()

	r := newNetworkRule(t, "||example.org^$"+modifier)

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
	assert.Equal(t, []string{"pc", "phone"}, perm.Values())
	assert.Equal(t, []string{"printer"}, rest.Values())

	perm, rest, err = parseCTags("device_pc0123", "|")
	require.NoError(t, err)
	assert.Equal(t, []string{"device_pc0123"}, perm.Values())
	assert.Equal(t, 0, rest.Len())

	perm, rest, err = parseCTags("pc|~phone|bad.", "|")
	require.Error(t, err)
	assert.Equal(t, []string{"pc"}, perm.Values())
	assert.Equal(t, []string{"phone"}, rest.Values())
}

func TestNetworkRule_cTagRules(t *testing.T) {
	t.Parallel()

	t.Run("permitted_one", func(t *testing.T) {
		t.Parallel()

		r := newNetworkRule(t, "||test.example^$ctag=pc")
		assert.Equal(t, []string{"pc"}, r.permittedClientTags.Values())

		req := NewRequestForHostname("test.example")
		req.ClientTags = container.NewSortedSliceSet("pc")
		assert.True(t, r.Match(req))

		req.ClientTags = nil
		assert.False(t, r.Match(req))
	})

	t.Run("permitted_list", func(t *testing.T) {
		t.Parallel()

		r := newNetworkRule(t, "||test.example^$ctag=phone|pc")
		assert.Equal(t, []string{"pc", "phone"}, r.permittedClientTags.Values())

		req := NewRequestForHostname("test.example")
		req.ClientTags = container.NewSortedSliceSet("phone", "other")
		assert.True(t, r.Match(req))

		req.ClientTags = nil
		assert.False(t, r.Match(req))
	})

	t.Run("permitted_restricted", func(t *testing.T) {
		t.Parallel()

		r := newNetworkRule(t, "||test.example^$ctag=~phone|pc")
		assert.Equal(t, []string{"pc"}, r.permittedClientTags.Values())
		assert.Equal(t, []string{"phone"}, r.restrictedClientTags.Values())

		req := NewRequestForHostname("test.example")
		req.ClientTags = container.NewSortedSliceSet("phone", "pc")
		assert.False(t, r.Match(req))

		req.ClientTags = container.NewSortedSliceSet("pc")
		assert.True(t, r.Match(req))

		req.ClientTags = container.NewSortedSliceSet("phone")
		assert.False(t, r.Match(req))
	})
}

// parseClientsTestCases is a list of test cases for parseClients tests and
// benchmarks.
var parseClientsTestCases = []struct {
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

func TestParseClients(t *testing.T) {
	t.Parallel()

	for _, tc := range parseClientsTestCases {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()

			p, r, err := parseClients(tc.input, '|')
			require.NoError(t, err)

			assert.Equal(t, tc.wantClients, p)
			assert.Equal(t, tc.wantRestricted, r)
		})
	}
}

func BenchmarkParseClients(b *testing.B) {
	for _, tc := range parseClientsTestCases {
		b.Run(tc.input, func(b *testing.B) {
			var p, r *clients
			var err error

			b.ReportAllocs()
			for b.Loop() {
				p, r, err = parseClients(tc.input, '|')
			}

			require.NoError(b, err)

			assert.Equal(b, tc.wantClients, p)
			assert.Equal(b, tc.wantRestricted, r)
		})
	}

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/urlfilter/rules
	//	cpu: Apple M1 Pro
	//	BenchmarkParseClients/127.0.0.1-8         	 4580858	       253.3 ns/op	     120 B/op	       5 allocs/op
	//	BenchmarkParseClients/127.0.0.1|127.0.0.2-8         	 2390991	       504.8 ns/op	     240 B/op	       9 allocs/op
	//	BenchmarkParseClients/127.0.0.1|~127.0.0.2-8        	 2302878	       513.7 ns/op	     256 B/op	      10 allocs/op
	//	BenchmarkParseClients/'Frank\'s_laptop'-8           	 3690001	       317.9 ns/op	     152 B/op	       7 allocs/op
	//	BenchmarkParseClients/~"Frank's_phone"-8            	 4984556	       241.2 ns/op	     104 B/op	       5 allocs/op
	//	BenchmarkParseClients/~"Frank's_phone"|'Frank\'s_laptop'-8         	 2201140	       545.8 ns/op	     272 B/op	      12 allocs/op
	//	BenchmarkParseClients/~'Mary\'s\,_John\'s\,_and_Boris\'s_laptops'-8         	 1981671	       605.3 ns/op	     296 B/op	       9 allocs/op
	//	BenchmarkParseClients/~Mom|~Dad|"Kids"-8                                    	 2588818	       469.9 ns/op	     296 B/op	      11 allocs/op
}

func BenchmarkNetworkRule_setOption(b *testing.B) {
	benchCases := []struct {
		name     string
		optName  string
		optValue string
	}{{
		name:     "dnstype",
		optName:  "dnstype",
		optValue: "AAAA|A|MX",
	}, {
		name:     "dnsrewrite",
		optName:  "dnsrewrite",
		optValue: "example.com",
	}, {
		name:     "client",
		optName:  "client",
		optValue: "192.0.2.1|name",
	}, {
		name:     "domain",
		optName:  "domain",
		optValue: "example.com|example.org",
	}, {
		name:     "match-case",
		optName:  "match-case",
		optValue: "",
	}, {
		name:     "ping",
		optName:  "~ping",
		optValue: "",
	}}

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			var err error
			rule := &NetworkRule{}

			b.ReportAllocs()
			for b.Loop() {
				err = rule.setOption(bc.optName, bc.optValue)
			}

			require.NoError(b, err)
		})
	}

	// Most recent results:
	// goos: darwin
	// pkg: github.com/AdguardTeam/urlfilter/rules
	// goarch: arm64
	// cpu: Apple M3
	// BenchmarkNetworkRule_setOption/dnstype-8         	11901484	        99.91 ns/op	      56 B/op	       2 allocs/op
	// BenchmarkNetworkRule_setOption/dnsrewrite-8      	11174571	       106.6 ns/op	      96 B/op	       2 allocs/op
	// BenchmarkNetworkRule_setOption/client-8          	 4485160	       281.2 ns/op	     176 B/op	       8 allocs/op
	// BenchmarkNetworkRule_setOption/domain-8          	10514790	       115.1 ns/op	      80 B/op	       3 allocs/op
	// BenchmarkNetworkRule_setOption/match-case-8      	161167903	       7.443 ns/op	       0 B/op	       0 allocs/op
	// BenchmarkNetworkRule_setOption/ping-8            	175328119	       6.873 ns/op	       0 B/op	       0 allocs/op
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

			r := newNetworkRule(t, tc.rule)
			b := newNetworkRule(t, tc.badfilter)

			tc.want(t, b.negatesBadfilter(r))
		})
	}
}
