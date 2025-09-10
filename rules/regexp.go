package rules

import (
	"strings"
)

const (
	// MaskAnyCharacter is a wildcard character.  It is used to represent any
	// set of characters.  This can also be an empty string or a string of any
	// length.
	MaskAnyCharacter = "*"

	// MaskPipe points to the beginning or the end of address.  The value
	// depends on the character placement in the mask.  For example, a rule
	// like "swf|" matches "http://example.com/annoyingflash.swf", but not
	// "http://example.com/swf/index.html".  "|http://example.org" matches
	// "http://example.org", but not "http://domain.com?url=http://example.org".
	MaskPipe = "|"

	// MaskSeparator is any character that isn't a letter, a digit, or one of
	// the following: '_', '-', '.', '%'.
	MaskSeparator = "^"

	// MaskStartURL matches the beginning of an address. It is used to not
	// specify a particular protocol and subdomain in address mask.  That is,
	// "||" stands for "http://*.", "https://*.", "ws://*.", and "wss://*." all
	// at once.
	MaskStartURL = "||"
)

// TODO(a.garipov):  Rename consistently.
const (
	// RegexAnyCharacter corresponds to [MaskAnyCharacter].
	RegexAnyCharacter = ".*"

	// RegexEndString corresponds to [MaskPipe] when it is at the end of a
	// pattern.
	RegexEndString = "$"

	// RegexSeparator corresponds to [MaskSeparator].
	RegexSeparator = "([^ a-zA-Z0-9.%_-]|$)"

	// RegexStartString corresponds to [MaskPipe] when it is at the beginning of
	// a pattern.
	RegexStartString = "^"

	// RegexStartURL corresponds to [MaskStartURL].
	RegexStartURL = `^(http|https|ws|wss)://([a-z0-9-_.]+\.)?`
)

// According to [MDN], the special characters are:
//
//	. * + ? ^ $ { } ( ) | [ ] / \
//
// Make an exception for our own special characters of "*", "|", and "^" which
// require additional processing.
//
// [MDN]: https://developer.mozilla.org/en/JavaScript/Reference/Global_Objects/regexp
var specialCharReplacer = strings.NewReplacer(
	`.`, `\.`,
	`+`, `\+`,
	`?`, `\?`,
	`$`, `\$`,
	`{`, `\{`,
	`}`, `\}`,
	`(`, `\(`,
	`)`, `\)`,
	`[`, `\[`,
	`]`, `\]`,
	`/`, `\/`,
	`\`, `\\`,
)

// patternToRegexp is a helper method for creating regular expressions from
// simple wildcard-based syntax which is used in basic filters.
//
// See https://adguard.com/kb/general/ad-filtering/create-own-filters/#basic-rules.
//
// TODO(a.garipov):  This requires a deep refactoring and optimization.
func patternToRegexp(pattern string) (reStr string) {
	if pattern == MaskStartURL ||
		pattern == MaskPipe ||
		pattern == MaskAnyCharacter ||
		pattern == "" {

		return RegexAnyCharacter
	}

	if isRegexPattern(pattern) {
		return pattern[1 : len(pattern)-1]
	}

	// Escape special characters.
	reStr = specialCharReplacer.Replace(pattern)

	// Escape "|" characters, but avoid escaping them in the special places.
	if strings.HasPrefix(reStr, MaskStartURL) {
		reStr = reStr[:len(MaskStartURL)] +
			strings.ReplaceAll(reStr[len(MaskStartURL):len(reStr)-1], MaskPipe, "\\"+MaskPipe) +
			reStr[len(reStr)-1:]
	} else {
		reStr = reStr[:len(MaskPipe)] +
			strings.ReplaceAll(reStr[len(MaskPipe):len(reStr)-1], MaskPipe, "\\"+MaskPipe) +
			reStr[len(reStr)-1:]
	}

	// Replace special URL masks.
	reStr = strings.ReplaceAll(reStr, MaskAnyCharacter, RegexAnyCharacter)
	reStr = strings.ReplaceAll(reStr, MaskSeparator, RegexSeparator)

	// Replace start URL and pipes.
	if strings.HasPrefix(reStr, MaskStartURL) {
		reStr = RegexStartURL + reStr[len(MaskStartURL):]
	} else if strings.HasPrefix(reStr, MaskPipe) {
		reStr = RegexStartString + reStr[len(MaskPipe):]
	}

	if strings.HasSuffix(reStr, MaskPipe) {
		reStr = reStr[:len(reStr)-1] + RegexEndString
	}

	return reStr
}
