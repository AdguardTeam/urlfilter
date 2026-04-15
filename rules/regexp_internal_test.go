package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPatternToRegexp(t *testing.T) {
	t.Parallel()

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
	}, {
		name:    "empty_regexp",
		pattern: "/",
		want:    "\\/",
	}, {
		name:    "empty_regexp",
		pattern: "//",
		want:    "",
	}, {
		// NOTE:  IP rules are not constrained by [RegexStartString] and
		// [RegexEndString].  Which means that a rule like "1.1.1.1" also
		// matches `221.1.1.122`.  The correct way to block an IP address is
		// something like `||1.1.1.1^`.
		name:    "ip",
		pattern: "192.0.2.0",
		want:    `192\.0\.2\.0`,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, patternToRegexp(tc.pattern))
		})
	}
}
