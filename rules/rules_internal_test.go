package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Common ListIDs for tests.
const (
	testListID ListID = 1
)

func TestSplitWithEscapeCharacter(t *testing.T) {
	str := "opt1,opt2"
	parts := splitWithEscapeCharacter(str, ',', '\\', false)
	require.Len(t, parts, 2)

	assert.Equal(t, "opt1", parts[0])
	assert.Equal(t, "opt2", parts[1])

	str = "opt1\\,opt2,,"
	parts = splitWithEscapeCharacter(str, ',', '\\', false)
	require.Len(t, parts, 1)

	assert.Equal(t, "opt1,opt2", parts[0])

	str = "opt1,\\opt2,,"
	parts = splitWithEscapeCharacter(str, ',', '\\', false)
	require.Len(t, parts, 2)

	assert.Equal(t, "opt1", parts[0])
	assert.Equal(t, "\\opt2", parts[1])

	str = "opt1,\\opt2,,"
	parts = splitWithEscapeCharacter(str, ',', '\\', true)
	require.Len(t, parts, 4)

	assert.Equal(t, "opt1", parts[0])
	assert.Equal(t, "\\opt2", parts[1])
	assert.Equal(t, "", parts[2])
	assert.Equal(t, "", parts[3])
}
