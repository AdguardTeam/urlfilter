package urlfilter

import (
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
)

// CosmeticEngine combines all the cosmetic rules and allows to quickly find all
// rules matching this or that hostname.
type CosmeticEngine struct {
	// TODO(a.garipov):  See if this can be replaced with an array.
	lookupTables map[rules.CosmeticRuleType]*cosmeticLookupTable
}

// NewCosmeticEngine builds a new cosmetic engine.  s must not be nil.
func NewCosmeticEngine(s *filterlist.RuleStorage) (e *CosmeticEngine) {
	e = &CosmeticEngine{
		lookupTables: map[rules.CosmeticRuleType]*cosmeticLookupTable{
			rules.CosmeticElementHiding: newCosmeticLookupTable(),
			rules.CosmeticCSS:           newCosmeticLookupTable(),
			rules.CosmeticJS:            newCosmeticLookupTable(),
		},
	}

	scanner := s.NewRuleStorageScanner()
	for scanner.Scan() {
		f, _ := scanner.Rule()
		rule, ok := f.(*rules.CosmeticRule)
		if ok {
			e.addRule(rule)
		}
	}

	return e
}

// addRule adds a new cosmetic rule to one of the lookup tables.  r must not be
// nil.
func (e *CosmeticEngine) addRule(r *rules.CosmeticRule) {
	switch r.Type {
	case rules.CosmeticElementHiding:
		e.lookupTables[rules.CosmeticElementHiding].addRule(r)
	default:
		// Ignore.
		//
		// TODO(a.garipov):  Implement.
	}
}

// StylesResult contains either element hiding or CSS rules.
type StylesResult struct {
	Generic        []string `json:"generic"`
	Specific       []string `json:"specific"`
	GenericExtCSS  []string `json:"genericExtCss"`
	SpecificExtCSS []string `json:"specificExtCss"`
}

// append adds cosmetic rule content to the appropriate style result field based
// on whether r is generic and requires extended CSS.  r must not be nil.
func (s *StylesResult) append(r *rules.CosmeticRule) {
	if r.IsGeneric() {
		if r.ExtendedCSS {
			s.GenericExtCSS = append(s.GenericExtCSS, r.Content)

			return
		}

		s.Generic = append(s.Generic, r.Content)
	} else {
		if r.ExtendedCSS {
			s.SpecificExtCSS = append(s.SpecificExtCSS, r.Content)

			return
		}

		s.Specific = append(s.Specific, r.Content)
	}
}

// ScriptsResult contains scripts to be executed on a page.
type ScriptsResult struct {
	Generic  []string
	Specific []string
}

// CosmeticResult represents all scripts and styles that needs to be injected
// into the page.
type CosmeticResult struct {
	ElementHiding StylesResult
	CSS           StylesResult
	JS            ScriptsResult
}

// Match builds scripts and styles that needs to be injected into the specified
// page.  hostname is the page hostname.  includeCSS defines if we should inject
// any CSS and element hiding rules (see $elemhide).  includeJS defines if we
// should inject JS into the page (see $jsinject).  includeGenericCSS defines if
// we should inject generic CSS and element hiding rules (see $generichide).
//
// TODO(ameshkov): Additionally, we should provide a method that writes result
// to an [io.Writer].
func (e *CosmeticEngine) Match(
	hostname string,
	includeCSS bool,
	includeJS bool,
	includeGenericCSS bool,
) (res CosmeticResult) {
	res = CosmeticResult{
		ElementHiding: StylesResult{},
		CSS:           StylesResult{},
		JS:            ScriptsResult{},
	}

	if !includeCSS {
		return res
	}

	c := e.lookupTables[rules.CosmeticElementHiding]
	if includeGenericCSS {
		for _, rule := range c.genericRules {
			if !c.isWhitelisted(hostname, rule) && rule.Match(hostname) {
				res.ElementHiding.append(rule)
			}
		}
	}

	for _, rule := range c.findByHostname(hostname) {
		res.ElementHiding.append(rule)
	}

	// TODO(ameshkov): Implement CosmeticCSS and CosmeticJS.

	return res
}

// cosmeticLookupTable is a helper structure to speed up cosmetic rules
// matching.
type cosmeticLookupTable struct {
	// byHostname is a map with rules grouped by the permitted domains names.
	byHostname map[string][]*rules.CosmeticRule

	// whiteList is a map with whitelist rules. It's key is the rule content.
	whitelist map[string][]*rules.CosmeticRule

	// genericRules is the list of generic cosmetic rules.
	genericRules []*rules.CosmeticRule
}

// newCosmeticLookupTable creates a new empty instance of the lookup table.
func newCosmeticLookupTable() (table *cosmeticLookupTable) {
	return &cosmeticLookupTable{
		byHostname:   map[string][]*rules.CosmeticRule{},
		genericRules: []*rules.CosmeticRule{},
		whitelist:    map[string][]*rules.CosmeticRule{},
	}
}

// addRule adds the specified rule to the lookup table.  r must not be nil.
func (c *cosmeticLookupTable) addRule(r *rules.CosmeticRule) {
	if r.Whitelist {
		rules := c.whitelist[r.Content]
		rules = append(rules, r)
		c.whitelist[r.Content] = rules

		return
	}

	if r.IsGeneric() {
		c.genericRules = append(c.genericRules, r)

		return
	}

	for _, hostname := range r.GetPermittedDomains() {
		rules := c.byHostname[hostname]
		rules = append(rules, r)
		c.byHostname[hostname] = rules
	}
}

// findByHostname looks for matching domain-specific rules.  Returns nil if
// there is no matching rules.
func (c *cosmeticLookupTable) findByHostname(hostname string) (rules []*rules.CosmeticRule) {
	rulesByHostname, found := c.byHostname[hostname]
	if !found {
		return rules
	}

	for _, rule := range rulesByHostname {
		if !c.isWhitelisted(hostname, rule) {
			rules = append(rules, rule)
		}
	}

	return rules
}

// isWhitelisted checks if this cosmetic rule is whitelisted on the specified
// hostname.  f must not be nil.
func (c *cosmeticLookupTable) isWhitelisted(
	hostname string,
	f *rules.CosmeticRule,
) (whiteListed bool) {
	list, found := c.whitelist[f.Content]
	if !found {
		return false
	}

	for _, rule := range list {
		if rule.Match(hostname) {
			return true
		}
	}

	return false
}
