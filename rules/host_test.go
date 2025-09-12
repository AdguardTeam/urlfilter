package rules_test

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHostRule(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		input      string
		name       string
		wantErrMsg string
		wantIP     netip.Addr
		wantHosts  []string
	}{{
		input:      "127.0.1.1       thishost.mydomain.org  thishost",
		name:       "hosts",
		wantIP:     netip.MustParseAddr("127.0.1.1"),
		wantErrMsg: "",
		wantHosts:  []string{"thishost.mydomain.org", "thishost"},
	}, {
		input:      "209.237.226.90  www.opensource.org",
		name:       "ip",
		wantIP:     netip.MustParseAddr("209.237.226.90"),
		wantErrMsg: "",
		wantHosts:  []string{"www.opensource.org"},
	}, {
		input:      "::1             localhost ip6-localhost ip6-loopback",
		name:       "localhost",
		wantIP:     netip.MustParseAddr("::1"),
		wantErrMsg: "",
		wantHosts:  []string{"localhost", "ip6-localhost", "ip6-loopback"},
	}, {
		input:      "example.org",
		name:       "ip_unspecified",
		wantIP:     netip.IPv4Unspecified(),
		wantErrMsg: "",
		wantHosts:  []string{"example.org"},
	}, {
		input: "#::1             test.example",
		name:  "comment",
		wantErrMsg: `rule "test.example": ParseAddr("#::1"): ` +
			`each colon-separated field must have at least one digit (at "#::1")`,
		wantIP:    netip.Addr{},
		wantHosts: nil,
	}, {
		input:      "||example.org",
		name:       "network",
		wantErrMsg: `rule "": invalid syntax`,
		wantIP:     netip.Addr{},
		wantHosts:  nil,
	}, {
		input:      "",
		name:       "empty",
		wantErrMsg: `rule "": invalid syntax`,
		wantIP:     netip.Addr{},
		wantHosts:  nil,
	}, {
		input:      "#",
		name:       "comment_hash",
		wantErrMsg: `rule "": invalid syntax`,
		wantIP:     netip.Addr{},
		wantHosts:  nil,
	}, {
		input:      "0.0.0.0 www.ruclicks.com  #[clicksagent.com]",
		name:       "comment_host",
		wantErrMsg: "",
		wantIP:     netip.IPv4Unspecified(),
		wantHosts:  []string{"www.ruclicks.com"},
	}, {
		input:      "_prebid_",
		name:       "cosmetic",
		wantErrMsg: `rule "": invalid syntax`,
		wantIP:     netip.Addr{},
		wantHosts:  nil,
	}, {
		input:      "_728x90.",
		name:       "cosmetic_dot",
		wantErrMsg: `rule "": invalid syntax`,
		wantIP:     netip.Addr{},
		wantHosts:  nil,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, err := rules.NewHostRule(tc.input, testListID)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)

			if tc.wantErrMsg != "" {
				assert.Nil(t, r)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, r)

			assert.Equal(t, testListID, r.GetFilterListID())
			assert.Equal(t, tc.wantIP, r.IP)
			assert.Equal(t, tc.wantHosts, r.Hostnames)
		})
	}
}

func TestHostRule_Match(t *testing.T) {
	t.Parallel()

	rule, err := rules.NewHostRule(
		"127.0.1.1       thishost.mydomain.org  thishost",
		testListID,
	)
	require.NoError(t, err)

	assert.True(t, rule.Match("thishost.mydomain.org"))
	assert.True(t, rule.Match("thishost"))
	assert.False(t, rule.Match("mydomain.org"))
	assert.False(t, rule.Match("example.org"))

	rule, err = rules.NewHostRule("209.237.226.90  www.opensource.org", testListID)
	require.NoError(t, err)

	assert.True(t, rule.Match("www.opensource.org"))
	assert.False(t, rule.Match("opensource.org"))
}

func FuzzHostRule_Match(f *testing.F) {
	r, err := rules.NewHostRule("127.0.1.1 example.test", testListID)
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

	f.Fuzz(func(t *testing.T, in string) {
		assert.NotPanics(t, func() {
			_ = r.Match(in)
		})
	})
}
