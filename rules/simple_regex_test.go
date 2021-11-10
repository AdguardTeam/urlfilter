package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPatternToRegex(t *testing.T) {
	testCases := []struct {
		name    string
		pattern string
		want    string
	}{{
		name:    "plain_url",
		pattern: "||example.org^",
		want:    RegexStartURL + "example\\.org" + RegexSeparator,
	}, {
		name:    "url_with_path",
		pattern: "|https://example.org/[*]^",
		want: RegexStartString + "https:\\/\\/example\\.org\\/\\[" + RegexAnyCharacter + "\\]" +
			RegexSeparator,
	}, {
		name:    "url_without_path",
		pattern: "|https://example.org|",
		want:    RegexStartString + "https:\\/\\/example\\.org" + RegexEndString,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, patternToRegexp(tc.pattern))
		})
	}
}
