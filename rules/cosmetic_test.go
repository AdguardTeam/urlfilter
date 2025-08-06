package rules_test

import (
	"testing"

	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCosmeticRule_Match(t *testing.T) {
	f, err := rules.NewCosmeticRule("##banner", testFilterListID)
	assert.Nil(t, err)
	assert.NotNil(t, f)
	assert.True(t, f.Match("example.org"))

	f, err = rules.NewCosmeticRule("example.org,~sub.example.org##banner", testFilterListID)
	assert.Nil(t, err)
	assert.NotNil(t, f)
	assert.True(t, f.Match("example.org"))
	assert.True(t, f.Match("test.example.org"))
	assert.False(t, f.Match("testexample.org"))
	assert.False(t, f.Match("sub.example.org"))
	assert.False(t, f.Match("sub.sub.example.org"))
}

func TestCosmeticRule_Match_wildcardTLD(t *testing.T) {
	f, err := rules.NewCosmeticRule("example.*##banner", testFilterListID)
	assert.Nil(t, err)
	assert.NotNil(t, f)

	assert.True(t, f.Match("example.org"))
	assert.True(t, f.Match("test.example.org"))
	assert.True(t, f.Match("example.co.uk"))
	assert.False(t, f.Match("example.local"))
	assert.False(t, f.Match("example.local.test"))
}

func FuzzCosmeticRule_Match(f *testing.F) {
	r, err := rules.NewCosmeticRule("example.*##banner", testFilterListID)
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
