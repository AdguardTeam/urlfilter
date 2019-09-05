package urlfilter

// MatchingResult contains all the rules matching a web request, and provides methods
// that define how a web request should be processed
type MatchingResult struct {
	// BasicRule - a rule matching the request.
	// It could lead to one of the following:
	// * block the request
	// * unblock the request (a regular whitelist rule or a document-level whitelist rule)
	// * modify the way cosmetic rules work for this request
	// * modify the response (see $redirect rules)
	BasicRule *NetworkRule

	// DocumentRule - a rule matching the request's referrer and having on of the following modifiers:
	// * $document -- this one basically disables everything
	// * $urlblock -- disables network-level rules (not cosmetic)
	// * $genericblock -- disables generic network-level rules
	//
	// Other document-level modifiers like $jsinject or $content will be ignored here
	// as they don't do anything
	DocumentRule *NetworkRule

	// CspRules - a set of rules modifying the response's content-security-policy
	// See $csp modifier
	CspRules []*NetworkRule

	// CookieRules - a set of rules modifying the request's and response's cookies
	// See $cookie modifier
	CookieRules []*NetworkRule

	// ReplaceRules -- a set of rules modifying the response's content
	// See $replace modifier
	ReplaceRules []*NetworkRule

	// StealthRule - this is a whitelist rule that negates stealth mode features
	// Note that the stealth rule can be be received from both rules and sourceRules
	StealthRule *NetworkRule
}

// NewMatchingResult creates an instance of the MatchingResult struct and fills it with the rules.
// rules - a set of rules matching the request URL
// sourceRules - a set of rules matching the referrer
func NewMatchingResult(rules []*NetworkRule, sourceRules []*NetworkRule) MatchingResult {
	result := MatchingResult{}

	// First of all, find document-level whitelist rules
	for _, rule := range sourceRules {
		if rule.isDocumentWhitelistRule() {
			if result.DocumentRule == nil || rule.isHigherPriority(result.DocumentRule) {
				result.DocumentRule = rule
			}
		}

		if rule.IsOptionEnabled(OptionStealth) {
			result.StealthRule = rule
		}
	}

	// Second - check if blocking rules (generic or all of them) are allowed
	// generic blocking rules are allowed by default
	genericAllowed := true
	// basic blocking rules are allowed by default
	basicAllowed := true
	if result.DocumentRule != nil {
		if result.DocumentRule.IsOptionEnabled(OptionUrlblock) {
			basicAllowed = false
		} else if result.DocumentRule.IsOptionEnabled(OptionGenericblock) {
			genericAllowed = false
		}
	}

	// Iterate through the list of rules and fill the MatchingResult struct
	for _, rule := range rules {
		switch {
		case rule.IsOptionEnabled(OptionCookie):
			result.CookieRules = append(result.CookieRules, rule)
		case rule.IsOptionEnabled(OptionReplace):
			result.ReplaceRules = append(result.ReplaceRules, rule)
		case rule.IsOptionEnabled(OptionCsp):
			result.CspRules = append(result.CspRules, rule)
		case rule.IsOptionEnabled(OptionStealth):
			result.StealthRule = rule
		default:
			// Check blocking rules against $genericblock / $urlblock
			if !rule.Whitelist {
				if !basicAllowed {
					continue
				}
				if !genericAllowed && rule.isGeneric() {
					continue
				}
			}

			if result.BasicRule == nil || rule.isHigherPriority(result.BasicRule) {
				result.BasicRule = rule
			}
		}
	}

	return MatchingResult{}
}
