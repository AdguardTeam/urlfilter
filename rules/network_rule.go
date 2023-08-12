package rules

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/urlfilter/filterutil"
)

const (
	maskWhiteList    = "@@"
	maskRegexRule    = "/"
	replaceOption    = "replace"
	optionsDelimiter = '$'
	escapeCharacter  = '\\'
)

// ErrTooWideRule is returned if the rule matches all urls but has no domain,
// denyallow, client or ctag restrictions.
var ErrTooWideRule errors.Error = "the rule is too wide, add domain, denyallow, client, " +
	"or ctag restrictions or make it more specific"

var (
	reEscapedOptionsDelimiter = regexp.MustCompile(regexp.QuoteMeta("\\$"))
	reRegexpBrackets1         = regexp.MustCompile(`([^\\])\(.*[^\\]\)`)
	reRegexpBrackets2         = regexp.MustCompile(`([^\\])\{.*[^\\]\}`)
	reRegexpBrackets3         = regexp.MustCompile(`([^\\])\[.*[^\\]\]`)
	reRegexpEscapedCharacters = regexp.MustCompile(`([^\\])\[a-zA-Z]`)
	reRegexpSpecialCharacters = regexp.MustCompile(`[\\^$*+?.()|[\]{}]`)
)

// NetworkRuleOption is the enumeration of various rule options
// In order to save memory, we store some options as a flag
type NetworkRuleOption uint64

// NetworkRuleOption enumeration
const (
	OptionThirdParty NetworkRuleOption = 1 << iota // $third-party modifier
	OptionMatchCase                                // $match-case modifier
	OptionImportant                                // $important modifier
	OptionBadfilter                                // $badfilter modifier

	// Whitelist rules modifiers
	// Each of them can disable part of the functionality

	OptionElemhide     // $elemhide modifier
	OptionGenerichide  // $generichide modifier
	OptionGenericblock // $genericblock modifier
	OptionJsinject     // $jsinject modifier
	OptionUrlblock     // $urlblock modifier
	OptionContent      // $content modifier
	OptionExtension    // $extension modifier

	// Whitelist -- specific to Stealth mode
	OptionStealth // $stealth

	// Content-modifying (TODO: get rid of, deprecated in favor of $redirect)
	OptionEmpty // $empty
	OptionMp4   // $mp4

	// Blocking
	OptionPopup // $popup

	// Advanced (TODO: Implement)
	OptionCsp      // $csp
	OptionReplace  // $replace
	OptionCookie   // $cookie
	OptionRedirect // $redirect

	// Blacklist-only options
	OptionBlacklistOnly = OptionPopup | OptionEmpty | OptionMp4

	// Whitelist-only options
	OptionWhitelistOnly = OptionElemhide | OptionGenericblock | OptionGenerichide |
		OptionJsinject | OptionUrlblock | OptionContent | OptionExtension |
		OptionStealth

	// Options supported by host-level network rules
	OptionHostLevelRulesOnly = OptionImportant | OptionBadfilter
)

// Count returns the count of enabled options
func (o NetworkRuleOption) Count() int {
	if o == 0 {
		return 0
	}

	flags := uint64(o)
	count := 0
	var i uint
	for i = 0; i < 64; i++ {
		mask := uint64(1 << i)
		if (flags & mask) == mask {
			count++
		}
	}
	return count
}

// NetworkRule is a basic filtering rule
// https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters#basic-rules
type NetworkRule struct {
	RuleText     string // RuleText is the original rule text
	Whitelist    bool   // true if this is an exception rule
	FilterListID int    // Filter list identifier
	Shortcut     string // the longest substring of the rule pattern with no special characters

	// DNSRewrite is the DNS rewrite rule, if any.
	DNSRewrite *DNSRewrite

	permittedDomains  []string // a list of permitted domains from the $domain modifier
	restrictedDomains []string // a list of restricted domains from the $domain modifier
	denyAllowDomains  []string // a list of excluded domains from the $denyallow modifier

	// permittedDNSTypes is the list of permitted DNS record type names from
	// the $dnstype modifier.
	permittedDNSTypes []RRType
	// restrictedDNSTypes is the list of restricted DNS record type names
	// from the $dnstype modifier.
	restrictedDNSTypes []RRType

	// https://github.com/AdguardTeam/AdGuardHome/issues/1081#issuecomment-575142737
	permittedClientTags  []string // a sorted list of permitted client tags from the $ctag modifier
	restrictedClientTags []string // a sorted list of restricted client tags from the $ctag modifier

	// https://github.com/AdguardTeam/AdGuardHome/issues/1761
	permittedClients  *clients // permitted clients from the $client modifier
	restrictedClients *clients // restricted clients from the $client modifier

	enabledOptions  NetworkRuleOption // Flag with all enabled rule options
	disabledOptions NetworkRuleOption // Flag with all disabled rule options

	permittedRequestTypes  RequestType // Flag with all permitted request types. 0 means ALL.
	restrictedRequestTypes RequestType // Flag with all restricted request types. 0 means NONE.

	pattern string         // Pattern is the basic rule pattern ready to be compiled to regex
	regex   *regexp.Regexp // Regex is the regular expression compiled from the pattern
	invalid bool           // Marker that the rule is invalid. Match will always return false in this case

	sync.Mutex
}

// NewNetworkRule parses the rule text and returns a filter rule
func NewNetworkRule(ruleText string, filterListID int) (r *NetworkRule, err error) {
	// split rule into pattern and options

	var pattern, options string
	var whitelist bool
	pattern, options, whitelist, err = parseRuleText(ruleText)
	if err != nil {
		return nil, err
	}

	r = &NetworkRule{
		RuleText:     ruleText,
		Whitelist:    whitelist,
		FilterListID: filterListID,
		pattern:      pattern,
	}

	// Parse options.
	if err = r.loadOptions(options); err != nil {
		return nil, err
	}

	// example.org/* -> example.org^
	if strings.HasSuffix(r.pattern, "/*") {
		r.pattern = r.pattern[:len(r.pattern)-len("/*")] + "^"
	}

	// validate rule
	if pattern == MaskStartURL || pattern == MaskPipe ||
		pattern == MaskAnyCharacter || pattern == "" ||
		len(pattern) < 3 {
		if len(r.permittedDomains) == 0 &&
			len(r.restrictedDomains) == 0 &&
			r.permittedClients.Len() == 0 &&
			r.restrictedClients.Len() == 0 &&
			len(r.permittedClientTags) == 0 &&
			len(r.restrictedClientTags) == 0 &&
			len(r.permittedDNSTypes) == 0 &&
			len(r.restrictedDNSTypes) == 0 &&
			len(r.denyAllowDomains) == 0 {
			// Rule matches too much and does not have any domain, client or ctag restrictions
			// We should not allow this kind of rules
			return nil, ErrTooWideRule
		}
	}

	r.loadShortcut()
	return r, nil
}

// Text returns the original rule text
// Implements the `Rule` interface
func (f *NetworkRule) Text() string {
	return f.RuleText
}

// GetFilterListID returns ID of the filter list this rule belongs to
func (f *NetworkRule) GetFilterListID() int {
	return f.FilterListID
}

// String returns original rule text
func (f *NetworkRule) String() string {
	return f.RuleText
}

// Match checks if this filtering rule matches the specified request.
func (f *NetworkRule) Match(r *Request) (ok bool) {
	switch {
	case
		!f.matchShortcut(r),
		f.IsOptionEnabled(OptionThirdParty) && !r.ThirdParty,
		f.IsOptionDisabled(OptionThirdParty) && r.ThirdParty,
		!f.matchRequestType(r.RequestType),
		!f.matchRequestDomain(r.Hostname, r.IsHostnameRequest),
		!f.matchSourceDomain(r.SourceHostname),
		!f.matchDNSType(r.DNSType),
		!f.matchClientTags(r.SortedClientTags),
		!f.matchClient(r.ClientName, r.ClientIP),
		!f.matchPattern(r):
		return false
	}

	return true
}

// IsOptionEnabled returns true if the specified option is enabled
func (f *NetworkRule) IsOptionEnabled(option NetworkRuleOption) bool {
	return (f.enabledOptions & option) == option
}

// IsOptionDisabled returns true if the specified option is disabled
func (f *NetworkRule) IsOptionDisabled(option NetworkRuleOption) bool {
	return (f.disabledOptions & option) == option
}

// GetPermittedDomains - returns an array of domains this rule is allowed on
func (f *NetworkRule) GetPermittedDomains() []string {
	return f.permittedDomains
}

// IsHostLevelNetworkRule checks if this rule can be used for hosts-level blocking
func (f *NetworkRule) IsHostLevelNetworkRule() bool {
	if len(f.permittedDomains) > 0 || len(f.restrictedDomains) > 0 {
		return false
	}

	if f.permittedRequestTypes != 0 && f.restrictedRequestTypes != 0 {
		return false
	}

	if f.disabledOptions != 0 {
		return false
	}

	if f.enabledOptions != 0 {
		return ((f.enabledOptions & OptionHostLevelRulesOnly) |
			(f.enabledOptions ^ OptionHostLevelRulesOnly)) == OptionHostLevelRulesOnly
	}

	return true
}

// isRegexPattern returns true if pattern may be treated as a regular expression
// rule.
func isRegexPattern(pattern string) bool {
	return len(pattern) > 1 && pattern[0] == '/' && pattern[len(pattern)-1] == '/'
}

// IsRegexRule returns true if the rule is a regular expression rule
func (f *NetworkRule) IsRegexRule() (ok bool) {
	return isRegexPattern(f.pattern)
}

// IsGeneric returns true if the rule is considered "generic"
// "generic" means that the rule is not restricted to a limited set of domains
// Please note that it might be forbidden on some domains, though.
func (f *NetworkRule) IsGeneric() bool {
	return len(f.permittedDomains) == 0
}

// IsHigherPriority checks if the rule has higher priority that the specified rule
// whitelist + $important > $important > whitelist > basic rules
// nolint: gocyclo
func (f *NetworkRule) IsHigherPriority(r *NetworkRule) bool {
	important := f.IsOptionEnabled(OptionImportant)
	rImportant := r.IsOptionEnabled(OptionImportant)

	if (f.Whitelist && important) && !(r.Whitelist && rImportant) {
		return true
	}

	if (r.Whitelist && rImportant) && !(f.Whitelist && important) {
		return false
	}

	if important && !rImportant {
		return true
	}

	if rImportant && !important {
		return false
	}

	if f.Whitelist && !r.Whitelist {
		return true
	}

	if r.Whitelist && !f.Whitelist {
		return false
	}

	redirect := f.IsOptionEnabled(OptionRedirect)
	rRedirect := r.IsOptionEnabled(OptionRedirect)
	if redirect && !rRedirect {
		// $redirect rules have "slightly" higher priority than regular basic rules
		return true
	}

	generic := f.IsGeneric()
	rGeneric := r.IsGeneric()
	if !generic && rGeneric {
		// specific rules have priority over generic rules
		return true
	}

	// More specific rules (i.e. with more modifiers) have higher priority
	count := f.enabledOptions.Count() + f.disabledOptions.Count() +
		f.permittedRequestTypes.Count() + f.restrictedRequestTypes.Count()
	if len(f.permittedDomains) != 0 || len(f.restrictedDomains) != 0 {
		count++
	}
	if len(f.permittedDNSTypes) != 0 || len(f.restrictedDNSTypes) != 0 {
		count++
	}
	if len(f.permittedClientTags) != 0 || len(f.restrictedClientTags) != 0 {
		count++
	}
	if f.permittedClients.Len() != 0 || f.restrictedClients.Len() != 0 {
		count++
	}
	if len(f.denyAllowDomains) != 0 {
		count++
	}
	rCount := r.enabledOptions.Count() + r.disabledOptions.Count() +
		r.permittedRequestTypes.Count() + r.restrictedRequestTypes.Count()
	if len(r.permittedDomains) != 0 || len(r.restrictedDomains) != 0 {
		rCount++
	}
	if len(r.permittedDNSTypes) != 0 || len(r.restrictedDNSTypes) != 0 {
		rCount++
	}
	if len(r.permittedClientTags) != 0 || len(r.restrictedClientTags) != 0 {
		rCount++
	}
	return count > rCount
}

// negatesBadfilter only makes sense when the "f" rule has a `badfilter` modifier
// it returns true if the "f" rule negates the specified "r" rule
func (f *NetworkRule) negatesBadfilter(r *NetworkRule) bool {
	switch {
	case
		!f.IsOptionEnabled(OptionBadfilter),
		f.Whitelist != r.Whitelist,
		f.pattern != r.pattern,
		f.permittedRequestTypes != r.permittedRequestTypes,
		f.restrictedRequestTypes != r.restrictedRequestTypes,
		(f.enabledOptions ^ OptionBadfilter) != r.enabledOptions,
		f.disabledOptions != r.disabledOptions,
		!stringArraysEquals(f.permittedDomains, r.permittedDomains),
		!stringArraysEquals(f.restrictedDomains, r.restrictedDomains),
		!stringArraysEquals(f.permittedClientTags, r.permittedClientTags),
		!stringArraysEquals(f.restrictedClientTags, r.restrictedClientTags),
		!f.permittedClients.Equal(r.permittedClients),
		!f.restrictedClients.Equal(r.restrictedClients):
		return false
	}

	return true
}

// isDocumentRule checks if the rule is a document-level whitelist rule
// This means that the rule is supposed to disable or modify blocking
// of the page subrequests.
// For instance, `@@||example.org^$urlblock` unblocks all sub-requests.
func (f *NetworkRule) isDocumentWhitelistRule() bool {
	return f.Whitelist && (f.IsOptionEnabled(OptionUrlblock) ||
		f.IsOptionEnabled(OptionGenericblock))
}

func (f *NetworkRule) preparePattern() (res int) {
	f.Lock()
	defer f.Unlock()

	switch {
	case f.regex != nil:
		return 1
	case f.invalid:
		return -1
	default:
		// Go on.
	}

	pattern := patternToRegexp(f.pattern)
	if pattern == RegexAnyCharacter {
		return 0
	}

	if !f.IsOptionEnabled(OptionMatchCase) {
		pattern = "(?i)" + pattern
	}

	var err error
	if f.regex, err = regexp.Compile(pattern); err != nil {
		f.invalid = true

		return -1
	}

	return 1
}

// matchPattern uses the regex pattern to match the request URL
func (f *NetworkRule) matchPattern(r *Request) bool {
	if res := f.preparePattern(); res == -1 {
		return false
	} else if res == 0 {
		return true
	}

	if f.shouldMatchHostname(r) {
		return f.regex.MatchString(r.Hostname)
	}

	return f.regex.MatchString(r.URL)
}

// shouldMatchHostname checks if we should match hostnames and not the URL
// this is important for the cases when we use urlfilter for DNS-level blocking
// Note, that even though we may work on a DNS-level, we should still sometimes
// match full URL instead:
// https://github.com/AdguardTeam/AdGuardHome/issues/1249
func (f *NetworkRule) shouldMatchHostname(r *Request) bool {
	if !r.IsHostnameRequest {
		return false
	}

	if strings.HasPrefix(f.pattern, MaskStartURL) ||
		strings.HasPrefix(f.pattern, "http://") ||
		strings.HasPrefix(f.pattern, "https://") ||
		strings.HasPrefix(f.pattern, "://") ||
		strings.HasPrefix(f.pattern, "*://") ||
		strings.HasPrefix(f.pattern, "ALL: ") ||
		strings.HasPrefix(f.pattern, "0 ") {
		return false
	}

	// Check if the pattern "/hostname." contains only allowed characters
	if len(f.pattern) > 3 && f.pattern[0] == '/' && f.pattern[len(f.pattern)-1] == '.' {
		for i := 1; i < len(f.pattern)-1; i++ {
			ch := f.pattern[i]
			if !((ch >= 'a' && ch <= 'z') ||
				(ch >= 'A' && ch <= 'Z') ||
				(ch >= '0' && ch <= '9') ||
				ch == '.' || ch == '-') {
				return true
			}
		}
		return false
	}

	return true
}

// matchShortcut simply checks if shortcut is a substring of the URL
func (f *NetworkRule) matchShortcut(r *Request) bool {
	return strings.Contains(r.URLLowerCase, f.Shortcut)
}

// matchRequestDomain checks if the filtering rule is allowed to match this
// request domain, e.g. it checks it against the $denyallow modifier. Please,
// pay attention at how $denyallow works:  the rule will work if the request
// hostname **does not** belong to $denyallow domains.  The idea is to allow
// rules that block anything EXCEPT FOR some domains.  For instance, if we have
// a website that we know to load a lot of third-party crap, but some of the
// domains are crucial for this website, we may want to add something like this:
// "*$script,domain=example.org,denyallow=essential1.com|essential2.com".
func (f *NetworkRule) matchRequestDomain(domain string, hostnameRequest bool) (ok bool) {
	if len(f.denyAllowDomains) == 0 {
		return true
	}

	// If this is a hostname request, we're probably dealing with DNS filtering.
	// In this case, we should avoid matching IP addresses here since they can
	// only come from CNAME filtering.  So regardless of whether it actually
	// matches the "denyallow" list, we consider that it does not.
	// Original issue: https://github.com/AdguardTeam/AdGuardHome/issues/3175.
	if hostnameRequest && filterutil.ParseIP(domain) != nil {
		return false
	}

	return !isDomainOrSubdomainOfAny(domain, f.denyAllowDomains)
}

// matchSourceDomain checks if the specified filtering rule is allowed on this
// domain e.g. it checks the domain against what's specified in the $domain
// modifier.
func (f *NetworkRule) matchSourceDomain(domain string) bool {
	if len(f.permittedDomains) == 0 && len(f.restrictedDomains) == 0 {
		return true
	}

	if len(f.restrictedDomains) > 0 {
		if isDomainOrSubdomainOfAny(domain, f.restrictedDomains) {
			// Domain or host is restricted
			// i.e. $domain=~example.org
			return false
		}
	}

	if len(f.permittedDomains) > 0 {
		if !isDomainOrSubdomainOfAny(domain, f.permittedDomains) {
			// Domain is not among permitted
			// i.e. $domain=example.org and we're checking example.com
			return false
		}
	}

	return true
}

// matchDNSType checks if the specified filtering rule is allowed for this DNS
// request record type.
func (f *NetworkRule) matchDNSType(rtype uint16) (allowed bool) {
	if len(f.permittedDNSTypes) == 0 && len(f.restrictedDNSTypes) == 0 {
		return true
	}

	for _, t := range f.restrictedDNSTypes {
		if rtype == t {
			return false
		}
	}

	if len(f.permittedDNSTypes) > 0 {
		for _, t := range f.permittedDNSTypes {
			if rtype == t {
				return true
			}
		}

		return false
	}

	return true
}

// Find an identical entry (case-sensitive) in two sorted arrays
// Return TRUE if found
func matchClientTagsSpecific(sortedRuleTags, sortedClientTags []string) bool {
	iRule := 0
	iClient := 0
	for iRule != len(sortedRuleTags) && iClient != len(sortedClientTags) {
		r := strings.Compare(sortedRuleTags[iRule], sortedClientTags[iClient])
		if r == 0 {
			return true
		} else if r < 0 {
			iRule++
		} else {
			iClient++
		}
	}
	return false
}

// Return TRUE if this rule matches with the tags associated with a client
func (f *NetworkRule) matchClientTags(sortedTags []string) bool {
	if len(f.restrictedClientTags) == 0 && len(f.permittedClientTags) == 0 {
		// the rule doesn't contain $ctag extension
		return true
	}
	if matchClientTagsSpecific(f.restrictedClientTags, sortedTags) {
		// matched by restricted client tag
		return false
	}
	if len(f.permittedClientTags) != 0 {
		// If the rule is permitted for specific tags only,
		// we should check whether our tag is among permitted or not
		// and return the result the result immediately
		return matchClientTagsSpecific(f.permittedClientTags, sortedTags)
	}
	return true
}

// matchClient returns TRUE if the rule matches with the specified client
// name -- client name (if any)
// ip -- client ip (if any)
func (f *NetworkRule) matchClient(name, ip string) bool {
	if f.restrictedClients.Len() == 0 && f.permittedClients.Len() == 0 {
		return true // the rule doesn't contain $client modifier
	}

	if f.restrictedClients.containsAny(name, ip) {
		// the client is in the restricted set
		return false
	}

	if f.permittedClients.Len() != 0 {
		// If the rule is permitted for specific client only,
		// we should check whether our client is among
		// permitted or not and return the result immediately
		return f.permittedClients.containsAny(name, ip)
	}

	// If we got here, permitted list is empty and the client is not among restricted
	return true
}

// matchRequestType checks if the specified request type matches the rule properties
func (f *NetworkRule) matchRequestType(requestType RequestType) bool {
	if f.permittedRequestTypes != 0 {
		if (f.permittedRequestTypes & requestType) != requestType {
			return false
		}
	}

	if f.restrictedRequestTypes != 0 {
		if (f.restrictedRequestTypes & requestType) == requestType {
			return false
		}
	}

	return true
}

// setRequestType permits or forbids the specified request type
func (f *NetworkRule) setRequestType(requestType RequestType, permitted bool) {
	if permitted {
		f.permittedRequestTypes |= requestType
	} else {
		f.restrictedRequestTypes |= requestType
	}
}

// setOptionEnabled enables or disables the specified option
// it can return error if this option cannot be used with this type of rules
func (f *NetworkRule) setOptionEnabled(option NetworkRuleOption, enabled bool) error {
	if f.Whitelist && (option&OptionBlacklistOnly) == option {
		return fmt.Errorf("modifier cannot be used in a whitelist rule: %v", option)
	}

	if !f.Whitelist && (option&OptionWhitelistOnly) == option {
		return fmt.Errorf("modifier cannot be used in a blacklist rule: %v", option)
	}

	if enabled {
		f.enabledOptions |= option
	} else {
		f.disabledOptions |= option
	}

	return nil
}

// loadOptions parses and adds all the options to f.
//
// See https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters#basic-rules.
func (f *NetworkRule) loadOptions(options string) (err error) {
	if options == "" {
		return nil
	}

	for _, o := range splitWithEscapeCharacter(options, ',', '\\', false) {
		if eqIdx := strings.IndexByte(o, '='); eqIdx > 0 {
			err = f.loadOption(o[:eqIdx], o[eqIdx+1:])
		} else {
			err = f.loadOption(o, "")
		}
		if err != nil {
			return err
		}
	}

	switch {
	case
		f.IsOptionEnabled(OptionJsinject),
		f.IsOptionEnabled(OptionElemhide),
		f.IsOptionEnabled(OptionContent),
		f.IsOptionEnabled(OptionUrlblock),
		f.IsOptionEnabled(OptionGenericblock),
		f.IsOptionEnabled(OptionGenerichide),
		f.IsOptionEnabled(OptionExtension),
		f.IsOptionEnabled(OptionPopup):
		// Rules of these types can be applied to documents only.
		f.permittedRequestTypes = TypeDocument
	default:
		// Go on.
	}

	return nil
}

// loadOption loads specified option with its value (optional)
// nolint:gocyclo
func (f *NetworkRule) loadOption(name, value string) error {
	switch name {
	// General options
	case "third-party", "~first-party":
		return f.setOptionEnabled(OptionThirdParty, true)
	case "~third-party", "first-party":
		return f.setOptionEnabled(OptionThirdParty, false)
	case "match-case":
		return f.setOptionEnabled(OptionMatchCase, true)
	case "~match-case":
		return f.setOptionEnabled(OptionMatchCase, false)
	case "important":
		return f.setOptionEnabled(OptionImportant, true)
	case "badfilter":
		return f.setOptionEnabled(OptionBadfilter, true)
	// $dnstype, the DNS request record type filter.
	case "dnstype":
		permitted, restricted, err := loadDNSTypes(value)
		f.permittedDNSTypes = permitted
		f.restrictedDNSTypes = restricted

		return err
	// $dnsrewrite, the DNS request rewrite filter.
	case "dnsrewrite":
		rewrite, err := loadDNSRewrite(value)
		f.DNSRewrite = rewrite

		return err
	// $domain -- limits the rule for selected source domains
	case "domain":
		permitted, restricted, err := loadDomains(value, "|")
		f.permittedDomains = permitted
		f.restrictedDomains = restricted
		return err

	// $denyallow -- disables the rule for the selected request domains
	case "denyallow":
		permitted, restricted, err := loadDomains(value, "|")
		if err != nil {
			return err
		}
		if len(restricted) > 0 || len(permitted) == 0 {
			return fmt.Errorf("invalid $denyallow value: %s", value)
		}
		f.denyAllowDomains = permitted
		return nil

	// $ctag - limits the rule for selected "Client tags"
	case "ctag":
		permitted, restricted, err := loadCTags(value, "|")
		if err == nil {
			f.permittedClientTags = permitted
			f.restrictedClientTags = restricted
		}
		return err

	// $client - limits the rule for selected "Clients" (either IP or client name)
	case "client":
		permitted, restricted, err := loadClients(value, '|')
		if err == nil {
			f.permittedClients = permitted
			f.restrictedClients = restricted
		}
		return err

	// Document-level whitelist rules
	case "elemhide":
		return f.setOptionEnabled(OptionElemhide, true)
	case "generichide":
		return f.setOptionEnabled(OptionGenerichide, true)
	case "genericblock":
		return f.setOptionEnabled(OptionGenericblock, true)
	case "jsinject":
		return f.setOptionEnabled(OptionJsinject, true)
	case "urlblock":
		return f.setOptionEnabled(OptionUrlblock, true)
	case "content":
		return f.setOptionEnabled(OptionContent, true)

	// $extension can be also disabled
	case "extension":
		return f.setOptionEnabled(OptionExtension, true)
	case "~extension":
		// $document must be specified before ~extension
		// TODO: Depends on options order, this is not good
		f.enabledOptions = f.enabledOptions ^ OptionExtension
		return nil

	// $document
	case "document":
		err := f.setOptionEnabled(OptionElemhide, true)
		// Ignore others
		_ = f.setOptionEnabled(OptionJsinject, true)
		_ = f.setOptionEnabled(OptionUrlblock, true)
		_ = f.setOptionEnabled(OptionContent, true)
		_ = f.setOptionEnabled(OptionExtension, true)
		return err

	// Stealth mode
	case "stealth":
		return f.setOptionEnabled(OptionStealth, true)

	// $popup blocking options
	case "popup":
		return f.setOptionEnabled(OptionPopup, true)

	// $empty and $mp4
	// TODO: Deprecate in favor of $redirect
	case "empty":
		return f.setOptionEnabled(OptionEmpty, true)
	case "mp4":
		return f.setOptionEnabled(OptionMp4, true)

	// Content type options
	case "script", "~script":
		f.setRequestType(TypeScript, name[0] != '~')
		return nil
	case "stylesheet", "~stylesheet":
		f.setRequestType(TypeStylesheet, name[0] != '~')
		return nil
	case "subdocument", "~subdocument":
		f.setRequestType(TypeSubdocument, name[0] != '~')
		return nil
	case "object", "~object":
		f.setRequestType(TypeObject, name[0] != '~')
		return nil
	case "image", "~image":
		f.setRequestType(TypeImage, name[0] != '~')
		return nil
	case "xmlhttprequest", "~xmlhttprequest":
		f.setRequestType(TypeXmlhttprequest, name[0] != '~')
		return nil
	case "media", "~media":
		f.setRequestType(TypeMedia, name[0] != '~')
		return nil
	case "font", "~font":
		f.setRequestType(TypeFont, name[0] != '~')
		return nil
	case "websocket", "~websocket":
		f.setRequestType(TypeWebsocket, name[0] != '~')
		return nil
	case "ping", "~ping":
		f.setRequestType(TypePing, name[0] != '~')
		return nil
	case "other", "~other":
		f.setRequestType(TypeOther, name[0] != '~')
		return nil
	}

	return fmt.Errorf("unknown filter modifier: %s=%s", name, value)
}

// loadShortcut extracts a shortcut from the pattern.
// shortcut is the longest substring of the pattern that does not contain
// any special characters
func (f *NetworkRule) loadShortcut() {
	var shortcut string
	if f.IsRegexRule() {
		shortcut = findRegexpShortcut(f.pattern)
	} else {
		shortcut = findShortcut(f.pattern)
	}

	// shortcut needs to be at least longer than 1 character
	if len(shortcut) > 1 {
		f.Shortcut = strings.ToLower(shortcut)
	}
}

// findShortcut searches for the longest substring of the pattern that does not
// contain any of the special characters which are:
//
//	*
//	^
//	|
func findShortcut(pattern string) (shortcut string) {
	for pattern != "" {
		i := strings.IndexAny(pattern, "*^|")
		if i == -1 {
			if len(pattern) > len(shortcut) {
				return pattern
			}

			break
		}

		if i > len(shortcut) {
			shortcut = pattern[:i]
		}
		pattern = pattern[i+1:]
	}

	return shortcut
}

// findRegexpShortcut searches for a shortcut inside of a regexp pattern.
// Shortcut in this case is a longest string with no REGEX special characters
// Also, we discard complicated regexps right away.
func findRegexpShortcut(pattern string) string {
	// strip backslashes
	pattern = pattern[1 : len(pattern)-1]

	if strings.Contains(pattern, "?") {
		// Do not mess with complex expressions which use lookahead
		// And with those using ? special character: https://github.com/AdguardTeam/AdguardBrowserExtension/issues/978
		return ""
	}

	// placeholder for a special character
	specialCharacter := "..."

	// (Dirty) prepend specialCharacter for the following replace calls to work properly
	pattern = specialCharacter + pattern

	//// Strip all types of brackets
	pattern = reRegexpBrackets1.ReplaceAllString(pattern, "$1"+specialCharacter)
	pattern = reRegexpBrackets2.ReplaceAllString(pattern, "$1"+specialCharacter)
	pattern = reRegexpBrackets3.ReplaceAllString(pattern, "$1"+specialCharacter)

	// Strip some escaped characters
	pattern = reRegexpEscapedCharacters.ReplaceAllString(pattern, "$1"+specialCharacter)

	// Split by special characters
	parts := reRegexpSpecialCharacters.Split(pattern, -1)
	longest := ""
	for _, part := range parts {
		if len(part) > len(longest) {
			longest = part
		}
	}

	return longest
}

// parseRuleText splits the rule's text into:
//
//	pattern, which is a basic rule pattern that can be easily converted into a regular expression;
//	options, a string containing all the rule's options.
//
// whitelist is true if the rule should unblock requests instead of blocking them.
func parseRuleText(ruleText string) (pattern, options string, whitelist bool, err error) {
	if ruleText == "" || ruleText == maskWhiteList {
		return "", "", whitelist, fmt.Errorf("the rule %s is too short", ruleText)
	}

	if strings.HasPrefix(ruleText, maskWhiteList) {
		whitelist = true
		ruleText = ruleText[len(maskWhiteList):]
	}

	// Avoid parsing options inside of a regex rule.
	if strings.HasPrefix(ruleText, maskRegexRule) &&
		strings.HasSuffix(ruleText, maskRegexRule) &&
		!strings.Contains(ruleText, replaceOption+"=") {
		return ruleText, "", whitelist, nil
	}

	hasEscaped := false
	for idx := len(ruleText) - 2; idx >= 0; idx-- {
		c := ruleText[idx]
		if c != optionsDelimiter {
			continue
		} else if !hasEscaped && idx > 0 && ruleText[idx-1] == escapeCharacter {
			hasEscaped = true

			continue
		}

		ruleText, options = ruleText[:idx], ruleText[idx+1:]
		if hasEscaped {
			options = reEscapedOptionsDelimiter.ReplaceAllString(options, string(optionsDelimiter))
		}

		// Exit the loop since the options delimiter has been found.
		break

	}

	return ruleText, options, whitelist, nil
}
