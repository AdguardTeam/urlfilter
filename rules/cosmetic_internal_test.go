package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCosmeticRule(t *testing.T) {
	f, err := NewCosmeticRule("##banner", 1)
	require.NotNil(t, f)
	require.NoError(t, err)

	assert.Equal(t, 1, f.FilterListID)
	assert.Equal(t, CosmeticElementHiding, f.Type)
	assert.False(t, f.Whitelist)
	assert.False(t, f.ExtendedCSS)
	assert.Empty(t, f.permittedDomains)
	assert.Empty(t, f.restrictedDomains)
	assert.Equal(t, "banner", f.Content)

	f, err = NewCosmeticRule("example.org,~sub.example.org##banner", 1)
	require.NotNil(t, f)
	require.NoError(t, err)
	require.Len(t, f.permittedDomains, 1)
	require.Len(t, f.restrictedDomains, 1)

	assert.Equal(t, CosmeticElementHiding, f.Type)
	assert.False(t, f.Whitelist)
	assert.False(t, f.ExtendedCSS)
	assert.Equal(t, "example.org", f.permittedDomains[0])
	assert.Equal(t, "sub.example.org", f.restrictedDomains[0])
	assert.Equal(t, "banner", f.Content)

	f, err = NewCosmeticRule("example.org#@#banner", 1)
	require.NotNil(t, f)
	require.NoError(t, err)
	require.Len(t, f.permittedDomains, 1)

	assert.Equal(t, CosmeticElementHiding, f.Type)
	assert.True(t, f.Whitelist)
	assert.False(t, f.ExtendedCSS)
	assert.Equal(t, "example.org", f.permittedDomains[0])
	assert.Empty(t, f.restrictedDomains)
	assert.Equal(t, "banner", f.Content)

	_, err = NewCosmeticRule("||example.org^", 1)
	require.Error(t, err)

	_, err = NewCosmeticRule("example.org## ", 1)
	require.Error(t, err)

	_, err = NewCosmeticRule("#@#.banner", 1)
	require.Error(t, err)
}
