package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindSorted(t *testing.T) {
	assert.Equal(t, -1, findSorted([]string{"b"}, "a"))
	assert.Equal(t, 0, findSorted([]string{"a"}, "a"))
	assert.Equal(t, 0, findSorted([]string{"a", "b"}, "a"))
	assert.Equal(t, 3, findSorted([]string{"a", "b", "c", "d"}, "d"))
}

func TestSplitWithEscapeCharacter(t *testing.T) {
	str := "opt1,opt2"
	parts := splitWithEscapeCharacter(str, ',', '\\', false)
	assert.Len(t, parts, 2)
	assert.Equal(t, "opt1", parts[0])
	assert.Equal(t, "opt2", parts[1])

	str = "opt1\\,opt2,,"
	parts = splitWithEscapeCharacter(str, ',', '\\', false)
	assert.Len(t, parts, 1)
	assert.Equal(t, "opt1,opt2", parts[0])

	str = "opt1,\\opt2,,"
	parts = splitWithEscapeCharacter(str, ',', '\\', false)
	assert.Len(t, parts, 2)
	assert.Equal(t, "opt1", parts[0])
	assert.Equal(t, "\\opt2", parts[1])

	str = "opt1,\\opt2,,"
	parts = splitWithEscapeCharacter(str, ',', '\\', true)
	assert.Len(t, parts, 4)
	assert.Equal(t, "opt1", parts[0])
	assert.Equal(t, "\\opt2", parts[1])
	assert.Equal(t, "", parts[2])
	assert.Equal(t, "", parts[3])
}
