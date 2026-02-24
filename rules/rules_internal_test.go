package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Common ListIDs for tests.
//
// NOTE:  Keep in sync with package uftest.
const (
	testListID ListID = 1
)

// newNetworkRule is a helper that wraps [NewNetworkRule].  It uses [testListID]
// as the list ID.
//
// NOTE:  Keep in sync with package uftest.
func newNetworkRule(tb testing.TB, text string) (r *NetworkRule) {
	tb.Helper()

	r, err := NewNetworkRule(text, testListID)
	require.NoError(tb, err)

	return r
}

func TestSplitWithEscapeCharacter(t *testing.T) {
	str := "opt1,opt2"
	parts := splitWithEscapeCharacter(str, ',', '\\')
	require.Len(t, parts, 2)

	assert.Equal(t, "opt1", parts[0])
	assert.Equal(t, "opt2", parts[1])

	str = "opt1\\,opt2,,"
	parts = splitWithEscapeCharacter(str, ',', '\\')
	require.Len(t, parts, 1)

	assert.Equal(t, "opt1,opt2", parts[0])

	str = "opt1,\\opt2,,"
	parts = splitWithEscapeCharacter(str, ',', '\\')
	require.Len(t, parts, 2)

	assert.Equal(t, "opt1", parts[0])
	assert.Equal(t, "\\opt2", parts[1])
}
