package rules_test

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHostRule(t *testing.T) {
	rule, err := rules.NewHostRule(
		"127.0.1.1       thishost.mydomain.org  thishost",
		testFilterListID,
	)
	assert.Nil(t, err)
	assert.NotNil(t, rule)
	assert.Equal(t, testFilterListID, rule.FilterListID)
	assert.Equal(t, netip.MustParseAddr("127.0.1.1"), rule.IP)
	assert.Equal(t, 2, len(rule.Hostnames))
	assert.Equal(t, "thishost.mydomain.org", rule.Hostnames[0])
	assert.Equal(t, "thishost", rule.Hostnames[1])

	rule, err = rules.NewHostRule("209.237.226.90  www.opensource.org", testFilterListID)
	assert.Nil(t, err)
	assert.NotNil(t, rule)
	assert.Equal(t, testFilterListID, rule.FilterListID)
	assert.Equal(t, netip.MustParseAddr("209.237.226.90"), rule.IP)
	assert.Equal(t, 1, len(rule.Hostnames))
	assert.Equal(t, "www.opensource.org", rule.Hostnames[0])

	rule, err = rules.NewHostRule(
		"::1             localhost ip6-localhost ip6-loopback",
		testFilterListID,
	)
	assert.Nil(t, err)
	assert.NotNil(t, rule)
	assert.Equal(t, testFilterListID, rule.FilterListID)
	assert.Equal(t, netip.MustParseAddr("::1"), rule.IP)
	assert.Equal(t, 3, len(rule.Hostnames))
	assert.Equal(t, "localhost", rule.Hostnames[0])
	assert.Equal(t, "ip6-localhost", rule.Hostnames[1])
	assert.Equal(t, "ip6-loopback", rule.Hostnames[2])

	rule, err = rules.NewHostRule("example.org", testFilterListID)
	assert.Nil(t, err)
	assert.NotNil(t, rule)
	assert.Equal(t, testFilterListID, rule.FilterListID)
	assert.Equal(t, netip.IPv4Unspecified(), rule.IP)
	assert.Equal(t, 1, len(rule.Hostnames))
	assert.Equal(t, "example.org", rule.Hostnames[0])

	rule, err = rules.NewHostRule(
		"#::1             localhost ip6-localhost ip6-loopback",
		testFilterListID,
	)
	assert.NotNil(t, err)
	assert.Nil(t, rule)

	rule, err = rules.NewHostRule("||example.org", testFilterListID)
	assert.NotNil(t, err)
	assert.Nil(t, rule)

	rule, err = rules.NewHostRule("", testFilterListID)
	assert.NotNil(t, err)
	assert.Nil(t, rule)

	rule, err = rules.NewHostRule("#", testFilterListID)
	assert.NotNil(t, err)
	assert.Nil(t, rule)

	rule, err = rules.NewHostRule("0.0.0.0 www.ruclicks.com  #[clicksagent.com]", testFilterListID)
	assert.Nil(t, err)
	assert.NotNil(t, rule)
	assert.Equal(t, testFilterListID, rule.FilterListID)
	assert.Equal(t, netip.IPv4Unspecified(), rule.IP)
	assert.Equal(t, 1, len(rule.Hostnames))
	assert.Equal(t, "www.ruclicks.com", rule.Hostnames[0])

	rule, err = rules.NewHostRule("_prebid_", testFilterListID)
	assert.Nil(t, rule)
	assert.NotNil(t, err)

	rule, err = rules.NewHostRule("_728x90.", testFilterListID)
	assert.Nil(t, rule)
	assert.NotNil(t, err)
}

func TestHostRule_Match(t *testing.T) {
	rule, err := rules.NewHostRule(
		"127.0.1.1       thishost.mydomain.org  thishost",
		testFilterListID,
	)
	assert.Nil(t, err)
	assert.True(t, rule.Match("thishost.mydomain.org"))
	assert.True(t, rule.Match("thishost"))
	assert.False(t, rule.Match("mydomain.org"))
	assert.False(t, rule.Match("example.org"))

	rule, err = rules.NewHostRule("209.237.226.90  www.opensource.org", testFilterListID)
	assert.Nil(t, err)
	assert.True(t, rule.Match("www.opensource.org"))
	assert.False(t, rule.Match("opensource.org"))
}

func FuzzHostRule_Match(f *testing.F) {
	r, err := rules.NewHostRule(
		"127.0.1.1 example.test",
		testFilterListID,
	)
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
