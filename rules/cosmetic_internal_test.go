package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCosmeticRule(t *testing.T) {
	t.Parallel()

	r, err := NewCosmeticRule("##banner", testListID)
	require.NotNil(t, r)
	require.NoError(t, err)

	assert.Equal(t, testListID, r.GetFilterListID())
	assert.Equal(t, CosmeticElementHiding, r.Type)
	assert.False(t, r.Whitelist)
	assert.False(t, r.ExtendedCSS)
	assert.Empty(t, r.permittedDomains)
	assert.Empty(t, r.restrictedDomains)
	assert.Equal(t, "banner", r.Content)

	r, err = NewCosmeticRule("example.org,~sub.example.org##banner", 1)
	require.NotNil(t, r)
	require.NoError(t, err)
	require.Len(t, r.permittedDomains, 1)
	require.Len(t, r.restrictedDomains, 1)

	assert.Equal(t, CosmeticElementHiding, r.Type)
	assert.False(t, r.Whitelist)
	assert.False(t, r.ExtendedCSS)
	assert.Equal(t, "example.org", r.permittedDomains[0])
	assert.Equal(t, "sub.example.org", r.restrictedDomains[0])
	assert.Equal(t, "banner", r.Content)

	r, err = NewCosmeticRule("example.org#@#banner", testListID)
	require.NotNil(t, r)
	require.NoError(t, err)
	require.Len(t, r.permittedDomains, 1)

	assert.Equal(t, CosmeticElementHiding, r.Type)
	assert.True(t, r.Whitelist)
	assert.False(t, r.ExtendedCSS)
	assert.Equal(t, "example.org", r.permittedDomains[0])
	assert.Empty(t, r.restrictedDomains)
	assert.Equal(t, "banner", r.Content)

	_, err = NewCosmeticRule("||example.org^", testListID)
	require.Error(t, err)

	_, err = NewCosmeticRule("example.org## ", testListID)
	require.Error(t, err)

	_, err = NewCosmeticRule("#@#.banner", testListID)
	require.Error(t, err)
}
