package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewElementHidingRule(t *testing.T) {
	f, err := NewCosmeticRule("##banner", 1)
	assert.Nil(t, err)
	assert.NotNil(t, f)
	assert.Equal(t, 1, f.FilterListID)
	assert.Equal(t, CosmeticElementHiding, f.Type)
	assert.False(t, f.Whitelist)
	assert.False(t, f.ExtendedCSS)
	assert.Empty(t, f.permittedDomains)
	assert.Empty(t, f.restrictedDomains)
	assert.Equal(t, "banner", f.Content)

	f, err = NewCosmeticRule("example.org,~sub.example.org##banner", 1)
	assert.Nil(t, err)
	assert.NotNil(t, f)
	assert.Equal(t, CosmeticElementHiding, f.Type)
	assert.False(t, f.Whitelist)
	assert.False(t, f.ExtendedCSS)
	assert.Equal(t, 1, len(f.permittedDomains))
	assert.Equal(t, 1, len(f.restrictedDomains))
	assert.Equal(t, "example.org", f.permittedDomains[0])
	assert.Equal(t, "sub.example.org", f.restrictedDomains[0])
	assert.Equal(t, "banner", f.Content)

	f, err = NewCosmeticRule("example.org#@#banner", 1)
	assert.Nil(t, err)
	assert.NotNil(t, f)
	assert.Equal(t, CosmeticElementHiding, f.Type)
	assert.True(t, f.Whitelist)
	assert.False(t, f.ExtendedCSS)
	assert.Equal(t, 1, len(f.permittedDomains))
	assert.Equal(t, "example.org", f.permittedDomains[0])
	assert.Empty(t, f.restrictedDomains)
	assert.Equal(t, "banner", f.Content)
}

func TestCosmeticRuleValidation(t *testing.T) {
	_, err := NewCosmeticRule("||example.org^", 1)
	assert.NotNil(t, err)

	_, err = NewCosmeticRule("example.org## ", 1)
	assert.NotNil(t, err)

	_, err = NewCosmeticRule("#@#.banner", 1)
	assert.NotNil(t, err)
}

func TestCosmeticRuleMatch(t *testing.T) {
	f, err := NewCosmeticRule("##banner", 1)
	assert.Nil(t, err)
	assert.NotNil(t, f)
	assert.True(t, f.Match("example.org"))

	f, err = NewCosmeticRule("example.org,~sub.example.org##banner", 1)
	assert.Nil(t, err)
	assert.NotNil(t, f)
	assert.True(t, f.Match("example.org"))
	assert.True(t, f.Match("test.example.org"))
	assert.False(t, f.Match("testexample.org"))
	assert.False(t, f.Match("sub.example.org"))
	assert.False(t, f.Match("sub.sub.example.org"))
}

func TestCosmeticRuleWildcardTLDMatch(t *testing.T) {
	f, err := NewCosmeticRule("example.*##banner", 1)
	assert.Nil(t, err)
	assert.NotNil(t, f)

	assert.True(t, f.Match("example.org"))
	assert.True(t, f.Match("test.example.org"))
	assert.True(t, f.Match("example.co.uk"))
	assert.False(t, f.Match("example.local"))
	assert.False(t, f.Match("example.local.test"))
}
