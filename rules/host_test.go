package rules_test

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHostRule(t *testing.T) {
	r, err := rules.NewHostRule(
		"127.0.1.1       thishost.mydomain.org  thishost",
		testListID,
	)
	require.NotNil(t, r)
	require.NoError(t, err)
	require.Len(t, r.Hostnames, 2)

	assert.Equal(t, testListID, r.FilterListID)
	assert.Equal(t, netip.MustParseAddr("127.0.1.1"), r.IP)
	assert.Equal(t, "thishost.mydomain.org", r.Hostnames[0])
	assert.Equal(t, "thishost", r.Hostnames[1])

	r, err = rules.NewHostRule("209.237.226.90  www.opensource.org", testListID)
	require.NotNil(t, r)
	require.NoError(t, err)
	require.Len(t, r.Hostnames, 1)

	assert.Equal(t, testListID, r.FilterListID)
	assert.Equal(t, netip.MustParseAddr("209.237.226.90"), r.IP)
	assert.Equal(t, "www.opensource.org", r.Hostnames[0])

	r, err = rules.NewHostRule(
		"::1             localhost ip6-localhost ip6-loopback",
		testListID,
	)
	require.NotNil(t, r)
	require.NoError(t, err)
	require.Len(t, r.Hostnames, 3)

	assert.Equal(t, testListID, r.FilterListID)
	assert.Equal(t, netip.MustParseAddr("::1"), r.IP)
	assert.Equal(t, "localhost", r.Hostnames[0])
	assert.Equal(t, "ip6-localhost", r.Hostnames[1])
	assert.Equal(t, "ip6-loopback", r.Hostnames[2])

	r, err = rules.NewHostRule("example.org", testListID)
	require.NotNil(t, r)
	require.NoError(t, err)
	require.Len(t, r.Hostnames, 1)

	assert.Equal(t, testListID, r.FilterListID)
	assert.Equal(t, netip.IPv4Unspecified(), r.IP)
	assert.Equal(t, "example.org", r.Hostnames[0])

	r, err = rules.NewHostRule(
		"#::1             localhost ip6-localhost ip6-loopback",
		testListID,
	)
	require.Nil(t, r)
	require.Error(t, err)

	r, err = rules.NewHostRule("||example.org", testListID)
	require.Nil(t, r)
	require.Error(t, err)

	r, err = rules.NewHostRule("", testListID)
	require.Nil(t, r)
	require.Error(t, err)

	r, err = rules.NewHostRule("#", testListID)
	require.Nil(t, r)
	require.Error(t, err)

	r, err = rules.NewHostRule("0.0.0.0 www.ruclicks.com  #[clicksagent.com]", testListID)
	require.NotNil(t, r)
	require.NoError(t, err)
	require.Len(t, r.Hostnames, 1)

	assert.Equal(t, testListID, r.FilterListID)
	assert.Equal(t, netip.IPv4Unspecified(), r.IP)
	assert.Equal(t, "www.ruclicks.com", r.Hostnames[0])

	r, err = rules.NewHostRule("_prebid_", testListID)
	require.Nil(t, r)
	require.Error(t, err)

	r, err = rules.NewHostRule("_728x90.", testListID)
	require.Nil(t, r)
	require.Error(t, err)
}

func TestHostRule_Match(t *testing.T) {
	rule, err := rules.NewHostRule(
		"127.0.1.1       thishost.mydomain.org  thishost",
		testListID,
	)
	assert.Nil(t, err)
	assert.True(t, rule.Match("thishost.mydomain.org"))
	assert.True(t, rule.Match("thishost"))
	assert.False(t, rule.Match("mydomain.org"))
	assert.False(t, rule.Match("example.org"))

	rule, err = rules.NewHostRule("209.237.226.90  www.opensource.org", testListID)
	assert.Nil(t, err)
	assert.True(t, rule.Match("www.opensource.org"))
	assert.False(t, rule.Match("opensource.org"))
}

func FuzzHostRule_Match(f *testing.F) {
	r, err := rules.NewHostRule(
		"127.0.1.1 example.test",
		testListID,
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
