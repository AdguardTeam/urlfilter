package urlfilter

import (
	"sort"
	"strings"
)

var (
	cosmeticRulesMarkers = []string{
		// HTML filtering
		"$$", "$@$",
		// Script rules
		"#%#", "#@%#",
		// Element hiding rules
		"##", "#@#",
		// CSS injection
		"#$#", "#@$#",
		// ExtCSS hiding rules
		"#?#", "#@?#",
		// ExtCSS injection rules
		"#$?#", "#@$?#",
	}
)

func init() {
	// This is important for "findRuleMarker" function to sort markers in this order
	sort.Sort(sort.Reverse(byLength(cosmeticRulesMarkers)))
}

// Rule is a base interface for all filtering rules
type Rule interface {
	// Text returns the original rule text
	Text() string

	// GetFilterListID returns ID of the filter list this rule belongs to
	GetFilterListID() int
}

// isComment checks if the line is a comment
func isComment(line string) bool {
	return strings.IndexByte(line, '!') == 0 || strings.IndexByte(line, '#') == 0
}

// isCosmetic checks if this is a cosmetic filtering rule
func isCosmetic(line string) bool {
	return findRuleMarker(line, cosmeticRulesMarkers, '#') != "" ||
		findRuleMarker(line, cosmeticRulesMarkers, '$') != ""
}

// findRuleMarker looks for a cosmetic rule marker in the rule text and returns the marker found or empty string if nothing found
// ruleText -- exact rule text
// markers -- an array of markers to check (IMPORTANT: sorted by length desc)
// firstMarkerChar -- first character of the marker we're looking for
func findRuleMarker(ruleText string, markers []string, firstMarkerChar byte) string {
	startIndex := strings.IndexByte(ruleText, firstMarkerChar)
	if startIndex == -1 {
		return ""
	}

	for _, marker := range markers {
		if startsAtIndexWith(ruleText, startIndex, marker) {
			return marker
		}
	}

	return ""
}

/**
 * Checks if the specified string starts with a substr at the specified index
 *
 * @param str        String to check
 * @param startIndex Index to start checking from
 * @param substr     Substring to check
 * @return boolean true if it does start
 */
// startsAtIndexWith checks if the specified string starts with a substr at the specified index
// str is the string to check
// startIndex is the index to start checking from
// substr is the substring to check
func startsAtIndexWith(str string, startIndex int, substr string) bool {
	if len(str)-startIndex < len(substr) {
		return false
	}

	for i := 0; i < len(substr); i++ {
		if str[startIndex+i] != substr[i] {
			return false
		}
	}

	return true
}
