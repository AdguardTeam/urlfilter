package rules

// CosmeticOption is the bitset of various content script options.
type CosmeticOption uint32

// Valid CosmeticOption masks.
const (
	// CosmeticOptionGenericCSS is set if generic elemhide and CSS rules are
	// enabled.  It can be disabled by a $generichide rule.
	CosmeticOptionGenericCSS CosmeticOption = 1 << iota

	// CosmeticOptionCSS is set if elemhide and CSS rules are enabled.  It can
	// be disabled by an $elemhide rule.
	CosmeticOptionCSS

	// CosmeticOptionJS is set if JS rules and scriptlets are enabled.  It can
	// be disabled by a $jsinject rule.
	CosmeticOptionJS

	// TODO(ameshkov):  Add support for these flags.  They are useful when
	// content script is injected into an iframe.  In this case we can check
	// what flags were applied to the top-level frame.

	CosmeticOptionSourceGenericCSS
	CosmeticOptionSourceCSS
	CosmeticOptionSourceJS

	CosmeticOptionAll  = CosmeticOptionGenericCSS | CosmeticOptionCSS | CosmeticOptionJS
	CosmeticOptionNone = CosmeticOption(0)
)

// MatchingResult contains all rules matching a web request and provides methods
// for processing of the request.
type MatchingResult struct {
	// BasicRule is a rule matching the request.  It could lead to one of the
	// following:
	//   - block the request;
	//   - unblock the request (a regular whitelist rule or a document-level
	//     whitelist rule);
	//   - modify the way cosmetic rules work for this request;
	//   - modify the response (see $redirect rules).
	BasicRule *NetworkRule

	// DocumentRule is a rule matching the request's referrer and having one of
	// the following modifiers:
	//   - $document: this one basically disables everything;
	//   - $urlblock: disables network-level rules (not cosmetic);
	//   - $genericblock: disables generic network-level rules.
	//
	// Other document-level modifiers like $jsinject or $content will be ignored
	// here as they don't do anything
	DocumentRule *NetworkRule

	// StealthRule is a whitelist rule that negates stealth-mode features.  Note
	// that the stealth rule can be received from both rules and sourceRules.
	//
	// See https://adguard.com/kb/general/ad-filtering/create-own-filters/#stealth-modifier.
	StealthRule *NetworkRule

	// CspRules are rules modifying the response's content-security-policy.  See
	// modifier $csp.
	CspRules []*NetworkRule

	// CookieRules are rules modifying the request's and response's cookies.
	// See modifier $cookie.
	CookieRules []*NetworkRule

	// ReplaceRules are rules modifying the response's content.  See modifier
	// $replace.
	ReplaceRules []*NetworkRule
}

// NewMatchingResult returns a new properly initialized *MatchingResult.  rules
// are the rules matching the request URL.  sourceRules are the rules matching
// the referrer.  Items of rules and sourceRules must not be nil.
func NewMatchingResult(rules, sourceRules []*NetworkRule) (res *MatchingResult) {
	res = &MatchingResult{}

	sourceRules = removeBadfilterRules(sourceRules)
	sourceRules = removeDNSRewriteRules(sourceRules)

	// Firstly, find document-level whitelist rules.
	res.fillFromSourceRules(sourceRules)

	// Secondly, check if blocking rules (generic or all of them) are allowed.
	// Generic and basic rules are allowed by default.
	genericAllowed := true
	basicAllowed := true
	if res.DocumentRule != nil {
		if res.DocumentRule.IsOptionEnabled(OptionUrlblock) {
			basicAllowed = false
		} else if res.DocumentRule.IsOptionEnabled(OptionGenericblock) {
			genericAllowed = false
		}
	}

	rules = removeBadfilterRules(rules)
	rules = removeDNSRewriteRules(rules)

	// Iterate through the list of rules and fill the MatchingResult struct.
	res.fillFromRules(rules, basicAllowed, genericAllowed)

	return res
}

// fillFromSourceRules processes sourceRules and fills the result struct.  Items
// of sourceRules must not be nil.
func (m *MatchingResult) fillFromSourceRules(sourceRules []*NetworkRule) {
	for _, rule := range sourceRules {
		if rule.isDocumentWhitelistRule() &&
			(m.DocumentRule == nil || rule.IsHigherPriority(m.DocumentRule)) {
			m.DocumentRule = rule
		}

		if rule.IsOptionEnabled(OptionStealth) {
			m.StealthRule = rule
		}
	}
}

// fillFromRules iterates given rules and fills the result struct.  Items of
// rules must not be nil.
func (m *MatchingResult) fillFromRules(rules []*NetworkRule, basicAllowed, genericAllowed bool) {
	for _, rule := range rules {
		m.fillFromRule(rule, basicAllowed, genericAllowed)
	}
}

// fillFromRule sets the consequent fields of the result struct for the given
// rule.  rule must not be nil.
func (m *MatchingResult) fillFromRule(rule *NetworkRule, basicAllowed, genericAllowed bool) {
	if m.appendModRule(rule) {
		return
	}

	// Check blocking rules against $genericblock / $urlblock.
	if !rule.Whitelist {
		if !basicAllowed {
			return
		}

		if !genericAllowed && rule.IsGeneric() {
			return
		}
	}

	if m.BasicRule == nil || rule.IsHigherPriority(m.BasicRule) {
		m.BasicRule = rule
	}
}

// appendModRule appends the given rule to the result struct if it has a
// suitable modifier option.  Returns true if the rule was appended.
func (m *MatchingResult) appendModRule(rule *NetworkRule) (ok bool) {
	switch {
	case rule.IsOptionEnabled(OptionCookie):
		m.CookieRules = append(m.CookieRules, rule)
	case rule.IsOptionEnabled(OptionReplace):
		m.ReplaceRules = append(m.ReplaceRules, rule)
	case rule.IsOptionEnabled(OptionCsp):
		m.CspRules = append(m.CspRules, rule)
	case rule.IsOptionEnabled(OptionStealth):
		m.StealthRule = rule
	default:
		return false
	}

	return true
}

// GetDNSBasicRule returns a rule that should be applied to the DNS request.
// Elements of rules must not be nil.
func GetDNSBasicRule(rules []*NetworkRule) (basicRule *NetworkRule) {
	rules = removeBadfilterRules(rules)
	rules = removeDNSRewriteRules(rules)

	for _, rule := range rules {
		switch {
		case rule.IsOptionEnabled(OptionReplace):
			// $replace rules have a higher priority than other basic rules
			// (including exception rules).
			return nil
		case rule.IsOptionEnabled(OptionCookie) ||
			rule.IsOptionEnabled(OptionCsp) ||
			rule.IsOptionEnabled(OptionStealth):
			// Skip rules with other options.
			continue
		default:
			if basicRule == nil || rule.IsHigherPriority(basicRule) {
				basicRule = rule
			}
		}
	}

	return basicRule
}

// GetBasicResult returns a rule that should be applied to the web request.
//
// Possible outcomes are:
//   - If r is nil, bypass the request.
//   - If r is a whitelist rule, bypass the request.
//   - If r is a blocking rule, block the request.
func (m *MatchingResult) GetBasicResult() (r *NetworkRule) {
	// 1. $replace rules have a higher priority than other basic rules
	//    (including exception rules).  So if a request corresponds to two
	//    different rules one of which has the $replace modifier, this rule will
	//    be applied.
	// 2. Document-level exception rules with $content or $document modifiers
	//    disable $replace rules for requests matching them.
	//
	// See https://adguard.com/kb/general/ad-filtering/create-own-filters/#replace-modifier.
	if m.ReplaceRules != nil {
		// TODO(ameshkov):  Implement the $replace selection algorithm:
		// 1. check that ReplaceRules aren't negated by themselves (for
		//    instance, that there's no @@||example.org^$replace rule);
		// 2. check that they aren't disabled by a document-level exception
		//    (check both DocumentRule and BasicRule);
		// 3. return nil if that is so.
		return nil
	}

	if m.BasicRule == nil {
		return m.DocumentRule
	}

	return m.BasicRule
}

// GetCosmeticOption returns the cosmetic options.
func (m *MatchingResult) GetCosmeticOption() (o CosmeticOption) {
	if m.BasicRule == nil || !m.BasicRule.Whitelist {
		return CosmeticOptionAll
	}

	o = CosmeticOptionAll

	if m.BasicRule.IsOptionEnabled(OptionElemhide) {
		o ^= CosmeticOptionCSS
		o ^= CosmeticOptionGenericCSS
	}

	if m.BasicRule.IsOptionEnabled(OptionGenerichide) {
		o ^= CosmeticOptionGenericCSS
	}

	if m.BasicRule.IsOptionEnabled(OptionJsinject) {
		o ^= CosmeticOptionJS
	}

	return o
}

// removeBadfilterRules looks if there are any matching $badfilter rules and
// removes matching bad filters from rules (see the $badfilter description
// for more info).
//
// TODO(f.setrakov): Improve the tests and refactor further.
func removeBadfilterRules(rules []*NetworkRule) (res []*NetworkRule) {
	var badfilterRules []*NetworkRule

	for _, badfilter := range rules {
		if badfilter.IsOptionEnabled(OptionBadfilter) {
			badfilterRules = append(badfilterRules, badfilter)
		}
	}

	if len(badfilterRules) > 0 {
		return filterNegatedRules(badfilterRules, rules)
	}

	return rules
}

// filterNegatedRules filters out rules that are negated by badfilter rules.
func filterNegatedRules(badfilterRules, rules []*NetworkRule) (res []*NetworkRule) {
	for _, badfilter := range badfilterRules {
		for _, rule := range rules {
			if !badfilter.negatesBadfilter(rule) && !rule.IsOptionEnabled(OptionBadfilter) {
				res = append(res, rule)
			}
		}
	}

	return res
}

// removeDNSRewriteRules removes DNS rewrite rules from rules and returns the
// filtered slice or the original slice if there were none.
func removeDNSRewriteRules(rules []*NetworkRule) (filtered []*NetworkRule) {
	// Assume that DNS rewrite rules are rare, and return the original slice if
	// there are none.

	var i int
	var found bool
	for i = range rules {
		if rules[i].DNSRewrite != nil {
			found = true

			break
		}
	}

	if !found {
		return rules
	}

	filtered = rules[:i:i]
	for ; i < len(rules); i++ {
		r := rules[i]
		if r.DNSRewrite == nil {
			filtered = append(filtered, r)
		}
	}

	return filtered
}
