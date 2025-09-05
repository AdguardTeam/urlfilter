package rules

import (
	"bytes"
	"slices"
	"strings"
)

// CosmeticRuleType is the enumeration of different cosmetic rules
type CosmeticRuleType uint8

// Valid CosmeticRuleType values.
const (
	// CosmeticElementHiding is for ## rules.
	//
	// See https://adguard.com/kb/general/ad-filtering/create-own-filters/#cosmetic-elemhide-rules.
	CosmeticElementHiding CosmeticRuleType = iota

	// CosmeticCSS is for #$# rules.
	//
	// See https://adguard.com/kb/general/ad-filtering/create-own-filters/#cosmetic-css-rules.
	CosmeticCSS

	// CosmeticJS is for #%# rules.
	//
	// See https://adguard.com/kb/general/ad-filtering/create-own-filters/#javascript-rules.
	CosmeticJS

	// CosmeticHTML is for $$ rules.
	//
	// See https://adguard.com/kb/general/ad-filtering/create-own-filters/#html-filtering-rules.
	//
	// TODO(ameshkov):  Move HTML filtering rules to a separate file/structure.
	CosmeticHTML
)

// cosmeticRuleMarker defines the type of cosmetic rule.
type cosmeticRuleMarker string

// cosmeticRuleMarker values.
//
// See the following sections in the documentation:
//   - https://adguard.com/kb/general/ad-filtering/create-own-filters/#cosmetic-elemhide-rules
//   - https://adguard.com/kb/general/ad-filtering/create-own-filters/#cosmetic-css-rules
//   - https://adguard.com/kb/general/ad-filtering/create-own-filters/#javascript-rules
//   - https://adguard.com/kb/general/ad-filtering/create-own-filters/#html-filtering-rules
const (
	markerElementHiding                cosmeticRuleMarker = "##"
	markerElementHidingException       cosmeticRuleMarker = "#@#"
	markerElementHidingExtCSS          cosmeticRuleMarker = "#?#"
	markerElementHidingExtCSSException cosmeticRuleMarker = "#@?#"

	markerCSS                cosmeticRuleMarker = "#$#"
	markerCSSException       cosmeticRuleMarker = "#@$#"
	markerCSSExtCSS          cosmeticRuleMarker = "#$?#"
	markerCSSExtCSSException cosmeticRuleMarker = "#@$?#"

	markerJS          cosmeticRuleMarker = "#%#"
	markerJSException cosmeticRuleMarker = "#@%#"

	markerHTML          cosmeticRuleMarker = "$$"
	markerHTMLException cosmeticRuleMarker = "$@$"
)

// cosmeticRulesMarkers contains all possible cosmetic rule markers.
var cosmeticRulesMarkers = []string{
	string(markerElementHiding),
	string(markerElementHidingException),
	string(markerElementHidingExtCSS),
	string(markerElementHidingExtCSSException),
	string(markerCSS),
	string(markerCSSException),
	string(markerCSSExtCSS),
	string(markerCSSExtCSSException),
	string(markerJS),
	string(markerJSException),
	string(markerHTML),
	string(markerHTMLException),
}

// cosmeticRuleMarkersFirstChars is used by [findCosmeticRuleMarker] function.
var cosmeticRuleMarkersFirstChars []byte

// TODO(a.garipov):  Consider removing.
func init() {
	// This is important for [findCosmeticRuleMarker] function to sort markers
	// in this order.
	slices.SortFunc(cosmeticRulesMarkers, func(a, b string) (res int) {
		return len(b) - len(a)
	})

	for _, marker := range cosmeticRulesMarkers {
		if bytes.IndexByte(cosmeticRuleMarkersFirstChars, marker[0]) == -1 {
			cosmeticRuleMarkersFirstChars = append(cosmeticRuleMarkersFirstChars, marker[0])
		}
	}
}

// CosmeticRule represents a cosmetic rule (element hiding, CSS, scriptlet).
type CosmeticRule struct {
	// RuleText is the original rule text.
	//
	// TODO(a.garipov):  Unexport.
	RuleText string

	// Content meaning depends on the rule type:
	//  - Element hiding: content is just a selector;
	//  - CSS: content is a selector + style definition;
	//  - JS: text of the script to be injected.
	Content string

	// permittedDomains is a list of permitted domains for this rule.
	permittedDomains []string

	// restrictedDomains is a list of restricted domains for this rule.
	restrictedDomains []string

	// FilterListID is a list identifier.
	//
	// TODO(a.garipov):  Unexport.
	FilterListID int

	// Type of the rule.
	Type CosmeticRuleType

	// Whitelist means that this rule is meant to disable rules with the same
	// content on the specified domains.
	//
	// See https://adguard.com/kb/general/ad-filtering/create-own-filters/#elemhide-exceptions
	//
	// TODO(a.garipov):  Unexport.
	Whitelist bool

	// ExtendedCSS means that this rule is supposed to be applied by the
	// Javascript library.
	//
	// See https://github.com/AdguardTeam/ExtendedCss.
	ExtendedCSS bool
}

// NewCosmeticRule parses the rule text and creates a rule.
func NewCosmeticRule(ruleText string, filterListID int) (r *CosmeticRule, err error) {
	r = &CosmeticRule{
		RuleText:     ruleText,
		FilterListID: filterListID,
	}

	index, m := findCosmeticRuleMarker(ruleText)
	if index == -1 {
		return nil, &RuleSyntaxError{
			msg:      "cannot find cosmetic marker",
			ruleText: ruleText,
		}
	}

	if index > 0 {
		// The marker is preceded by the list of domains.  Parse immediately.
		domains := ruleText[:index]
		r.permittedDomains, r.restrictedDomains, err = loadDomains(domains, ",")
		if err != nil {
			return nil, &RuleSyntaxError{
				msg:      "cannot load domains",
				ruleText: ruleText,
			}
		}
	}

	r.Content = strings.TrimSpace(ruleText[index+len(m):])
	if r.Content == "" {
		return nil, &RuleSyntaxError{
			msg:      "empty rule content",
			ruleText: ruleText,
		}
	}

	switch cosmeticRuleMarker(m) {
	case markerElementHiding:
		r.Type = CosmeticElementHiding
	case markerElementHidingException:
		r.Type = CosmeticElementHiding
		r.Whitelist = true
	default:
		return nil, ErrUnsupportedRule
	}

	if r.Whitelist && len(r.permittedDomains) == 0 {
		return nil, &RuleSyntaxError{
			msg:      "whitelist rule must have at least one domain specified",
			ruleText: ruleText,
		}
	}

	// TODO(ameshkov): validate content
	// TODO(ameshkov): detect ExtCSS pseudo-classes

	return r, nil
}

// type check
var _ Rule = (*CosmeticRule)(nil)

// Text implements the [Rule] interface for *CosmeticRule.
func (r *CosmeticRule) Text() (s string) {
	return r.RuleText
}

// GetFilterListID implements the [Rule] interface for *CosmeticRule.
func (r *CosmeticRule) GetFilterListID() (id int) {
	return r.FilterListID
}

// String returns original rule text.
func (r *CosmeticRule) String() (s string) {
	return r.RuleText
}

// GetPermittedDomains returns a slice of permitted domains.
func (r *CosmeticRule) GetPermittedDomains() []string {
	return r.permittedDomains
}

// IsGeneric returns true if r is not limited to a specific domain.
func (r *CosmeticRule) IsGeneric() (ok bool) {
	return len(r.permittedDomains) == 0
}

// Match returns true if this rule can be used on the specified hostname.
func (r *CosmeticRule) Match(hostname string) (ok bool) {
	// TODO(ameshkov):  Improve hosts matching, start using a better approach,
	// like token-based maps.

	if len(r.permittedDomains) == 0 && len(r.restrictedDomains) == 0 {
		return true
	}

	if len(r.restrictedDomains) > 0 {
		if isDomainOrSubdomainOfAny(hostname, r.restrictedDomains) {
			// Domain or host is restricted, i.e. "$domain=~example.org".
			return false
		}
	}

	if len(r.permittedDomains) > 0 {
		if !isDomainOrSubdomainOfAny(hostname, r.permittedDomains) {
			// Domain is not among permitted, i.e. "$domain=example.org" and
			// we're checking example.com.
			return false
		}
	}

	return true
}

// findCosmeticRuleMarker looks for a cosmetic rule marker in the rule text and
// returns the start index and the marker found.  If nothing found, idx is -1.
func findCosmeticRuleMarker(ruleText string) (idx int, marker string) {
	for _, firstMarkerChar := range cosmeticRuleMarkersFirstChars {
		startIndex := strings.IndexByte(ruleText, firstMarkerChar)
		if startIndex == -1 {
			continue
		}

		// Handling false positives while looking for cosmetic rules in host
		// files.  For instance, it could look like this:
		//
		//	0.0.0.0 jackbootedroom.com  ## phishing
		if startIndex > 0 && ruleText[startIndex-1] == ' ' {
			continue
		}

		for _, marker = range cosmeticRulesMarkers {
			if startsAtIndexWith(ruleText, startIndex, marker) {
				return startIndex, marker
			}
		}
	}

	return -1, ""
}

// startsAtIndexWith checks if s starts with substr at startIdx.
func startsAtIndexWith(s string, startIdx int, substr string) (ok bool) {
	if len(s)-startIdx < len(substr) {
		return false
	}

	for i := 0; i < len(substr); i++ {
		if s[startIdx+i] != substr[i] {
			return false
		}
	}

	return true
}
