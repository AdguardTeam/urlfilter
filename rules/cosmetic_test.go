package rules_test

import (
	"testing"

	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCosmeticRule_Match(t *testing.T) {
	r, err := rules.NewCosmeticRule("##banner", testListID)
	require.NotNil(t, r)
	require.NoError(t, err)

	assert.True(t, r.Match("example.org"))

	r, err = rules.NewCosmeticRule("example.org,~sub.example.org##banner", testListID)
	require.NotNil(t, r)
	require.NoError(t, err)

	assert.True(t, r.Match("example.org"))
	assert.True(t, r.Match("test.example.org"))
	assert.False(t, r.Match("testexample.org"))
	assert.False(t, r.Match("sub.example.org"))
	assert.False(t, r.Match("sub.sub.example.org"))
}

func TestCosmeticRule_Match_wildcardTLD(t *testing.T) {
	r, err := rules.NewCosmeticRule("example.*##banner", testListID)
	require.NotNil(t, r)
	require.NoError(t, err)

	assert.True(t, r.Match("example.org"))
	assert.True(t, r.Match("test.example.org"))
	assert.True(t, r.Match("example.co.uk"))
	assert.False(t, r.Match("example.local"))
	assert.False(t, r.Match("example.local.test"))
}

func FuzzCosmeticRule_Match(f *testing.F) {
	r, err := rules.NewCosmeticRule("example.*##banner", testListID)
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
