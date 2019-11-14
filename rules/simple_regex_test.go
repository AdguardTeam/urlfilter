package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPatternToRegex(t *testing.T) {
	regex := patternToRegexp("||example.org^")
	expected := RegexStartURL + "example\\.org" + RegexSeparator
	assert.Equal(t, expected, regex)

	regex = patternToRegexp("|https://example.org|")
	expected = RegexStartString + "https:\\/\\/example\\.org" + RegexEndString
	assert.Equal(t, expected, regex)

	regex = patternToRegexp("|https://example.org/[*]^")
	expected = RegexStartString + "https:\\/\\/example\\.org\\/\\[" + RegexAnyCharacter + "\\]" + RegexSeparator
	assert.Equal(t, expected, regex)
}
