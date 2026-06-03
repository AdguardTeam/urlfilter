package rules

import (
	"fmt"
	"math/bits"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/mathutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/urlfilter/internal/geoip"
)

// Parts of rules.
const (
	maskWhiteList    = "@@"
	maskRegexRule    = "/"
	replaceOption    = "replace"
	optionsDelimiter = '$'
	escapeCharacter  = '\\'
)

// Common regular expressions.
var (
	regexpBracketsCurly           = regexp.MustCompile(`([^\\])\{.*[^\\]\}`)
	regexpBracketsRound           = regexp.MustCompile(`([^\\])\(.*[^\\]\)`)
	regexpBracketsSquare          = regexp.MustCompile(`([^\\])\[.*[^\\]\]`)
	regexpEscapedCharacters       = regexp.MustCompile(`([^\\])\[a-zA-Z]`)
	regexpEscapedOptionsDelimiter = regexp.MustCompile(regexp.QuoteMeta("\\$"))
	regexpSpecialCharacters       = regexp.MustCompile(`[\\^$*+?.()|[\]{}]`)
)

// minPatternLen is the minimum valid pattern length for network rule.
const minPatternLen = 4

// NetworkRuleOption is the bitset of various rule options.
type NetworkRuleOption uint64

// NetworkRuleOption masks.
//
// TODO(a.garipov):  Rename to NetworkOptionFoo etc.
const (
	// OptionThirdParty means that the $third-party modifier is set.
	OptionThirdParty NetworkRuleOption = 1 << iota

	// OptionMatchCase means that the $match-case modifier is set.
	OptionMatchCase

	// OptionImportant means that the $important modifier is set.
	OptionImportant

	// OptionBadfilter means that the $badfilter modifier is set.
	OptionBadfilter

	// OptionElemhide means that the $elemhide modifier is set.
	OptionElemhide

	// OptionGenerichide means that the $generichide modifier is set.
	OptionGenerichide

	// OptionGenericblock means that the $genericblock modifier is set.
	OptionGenericblock

	// OptionJsinject means that the $jsinject modifier is set.
	OptionJsinject

	// OptionUrlblock means that the $urlblock modifier is set.
	OptionUrlblock

	// OptionContent means that the $content modifier is set.
	OptionContent

	// OptionExtension means that the $extension modifier is set.
	OptionExtension

	// OptionStealth means that the $stealth modifier is set.
	OptionStealth

	// OptionEmpty means that the $empty modifier is set.
	//
	// TODO(ameshkov):  Get rid of it, as it is deprecated in favor of
	// $redirect.
	OptionEmpty

	// OptionMp4 means that the $mp4 modifier is set.
	//
	// TODO(ameshkov):  Get rid of it, as it is deprecated in favor of
	// $redirect.
	OptionMp4

	// OptionPopup means that the $popup modifier is set.
	OptionPopup

	// OptionCsp means that the $csp modifier is set.
	//
	// TODO(ameshkov):  Implement.
	OptionCsp

	// OptionReplace means that the $replace modifier is set.
	//
	// TODO(ameshkov):  Implement.
	OptionReplace

	// OptionCookie means that the $cookie modifier is set.
	//
	// TODO(ameshkov):  Implement.
	OptionCookie

	// OptionRedirect means that the $redirect modifier is set.
	//
	// TODO(ameshkov):  Implement.
	OptionRedirect

	// OptionBlacklistOnly are the blacklist-only options.
	OptionBlacklistOnly = OptionEmpty |
		OptionMp4 |
		OptionPopup

	// OptionWhitelistOnly are the whitelist-only options.
	OptionWhitelistOnly = OptionContent |
		OptionElemhide |
		OptionExtension |
		OptionGenericblock |
		OptionGenerichide |
		OptionJsinject |
		OptionStealth |
		OptionUrlblock

	// OptionHostLevelRulesOnly are the options supported by host-level network
	// rules.
	OptionHostLevelRulesOnly = OptionImportant | OptionBadfilter
)

// Count returns the number of enabled options.
func (o NetworkRuleOption) Count() (n int) {
	return bits.OnesCount64(uint64(o))
}

// unknownLocationPolicy determines the match behavior for requests with unknown
// location.
type unknownLocationPolicy = uint8

const (
	// unknownLocationPolicyNone means that there is no special behavior for
	// matching requests with unknown location.
	unknownLocationPolicyNone = iota

	// unknownLocationPolicyPermit means that only requests with unknown
	// location must be permitted.
	unknownLocationPolicyPermit

	// unknownLocationPolicyRestrict means that requests with unknown location
	// must be restricted.
	unknownLocationPolicyRestrict
)

// NetworkRule is a basic filtering rule.
//
// See https://adguard.com/kb/general/ad-filtering/create-own-filters/#basic-rules.
type NetworkRule struct {
	// permittedClients are permitted clients from the $client modifier.
	//
	// See https://github.com/AdguardTeam/AdGuardHome/issues/1761.
	permittedClients *clients

	// restrictedClients are restricted clients from the $client modifier.
	//
	// See https://github.com/AdguardTeam/AdGuardHome/issues/1761.
	restrictedClients *clients

	// DNSRewrite is the DNS rewrite rule, if any.
	DNSRewrite *DNSRewrite

	// regexp is the regular expression compiled from the pattern.
	regexp *regexp.Regexp

	// permittedClientTags is a sorted list of permitted client tags from the
	// $ctag modifier.
	//
	// See https://github.com/AdguardTeam/AdGuardHome/issues/1081#issuecomment-575142737.
	permittedClientTags *container.SortedSliceSet[string]

	// restrictedClientTags is a sorted list of restricted client tags from the
	// $ctag modifier.
	//
	// See https://github.com/AdguardTeam/AdGuardHome/issues/1081#issuecomment-575142737.
	restrictedClientTags *container.SortedSliceSet[string]

	// text is the original rule text.
	text string

	// permittedASNs is a sorted list of permitted ASNs from the $respgeo
	// modifier.
	permittedASNs *container.SortedSliceSet[geoip.ASN]

	// restrictedASNs is a sorted list of restricted ASNs from the $respgeo
	// modifier.
	restrictedASNs *container.SortedSliceSet[geoip.ASN]

	// permittedCountries is a sorted list of permitted countries from the
	// $respgeo modifier.
	permittedCountries *container.SortedSliceSet[geoip.Country]

	// restrictedCountries is a sorted list of restricted countries from the
	// $respgeo modifier.
	restrictedCountries *container.SortedSliceSet[geoip.Country]

	// Shortcut is the longest substring of the rule pattern with no special
	// characters.
	Shortcut string

	// pattern is the basic rule pattern ready to be compiled to regex.
	pattern string

	// permittedDomains is a list of permitted domains from the $domain
	// modifier.
	permittedDomains []string

	// restrictedDomains is a list of restricted domains from the $domain
	// modifier.
	restrictedDomains []string

	// denyAllowDomains is a list of excluded domains from the $denyallow
	// modifier.
	denyAllowDomains []string

	// permittedDNSTypes is the list of permitted DNS record type names from
	// the $dnstype modifier.
	permittedDNSTypes []RRType

	// restrictedDNSTypes is the list of restricted DNS record type names from
	// the $dnstype modifier.
	restrictedDNSTypes []RRType

	// id is a filter list identifier.
	id ListID

	// enabledOptions are the flags with all enabled rule options.
	enabledOptions NetworkRuleOption

	// disabledOptions are the flags with all disabled rule options.
	disabledOptions NetworkRuleOption

	// initOnce makes sure that init is only called once.
	//
	// NOTE: The use of non-pointer version is intentional, as it lowers the
	// amount of allocations.  Also do not use sync.OnceFunc, since it allocates
	// even more.
	initOnce sync.Once

	// permittedRequestTypes are the flags with all permitted request types. 0
	// means ALL.
	permittedRequestTypes RequestType

	// restrictedRequestTypes are the flags with all restricted request types. 0
	// means NONE.
	restrictedRequestTypes RequestType

	// unknownLocationPolicy determines the strategy for matching requests with
	// unknown location.
	unknownLocationPolicy unknownLocationPolicy

	// Whitelist is true if this is an exception rule.
	//
	// TODO(a.garipov):  Consider unexporting.
	Whitelist bool

	// matchesAll shows if the rule matches everything.
	matchesAll bool

	// matchesNothing shows if the rule matches nothing.
	matchesNothing bool
}

// NewNetworkRule parses the rule text and returns a filter rule.
func NewNetworkRule(ruleText string, id ListID) (r *NetworkRule, err error) {
	pattern, options, whitelist, err := parseRuleText(ruleText)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	r = &NetworkRule{
		text:           ruleText,
		Whitelist:      whitelist,
		id:             id,
		pattern:        pattern,
		matchesNothing: pattern == MaskSeparator,
	}

	if err = r.loadOptions(options); err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	// Normalize rules like "example.org/*" into "example.org^".
	if strings.HasSuffix(r.pattern, "/*") {
		r.pattern = r.pattern[:len(r.pattern)-len("/*")] + MaskSeparator
	}

	if r.isTooWide(pattern) {
		return nil, ErrTooWideRule
	}

	r.setShortcut()

	return r, nil
}

// isTooWide returns true if r is too wide.  r must not be nil
func (r *NetworkRule) isTooWide(pattern string) (ok bool) {
	// Rule matches too much and does not have any domain, client or ctag
	// restrictions.  We should not allow this kind of rules.

	return isPatternTooWide(pattern) && r.hasNoRestrictions()
}

// isPatternTooWide returns true if the pattern is too generic.
func isPatternTooWide(pattern string) (ok bool) {
	return pattern == MaskStartURL ||
		pattern == MaskPipe ||
		pattern == MaskAnyCharacter ||
		pattern == "" ||
		len(pattern) < 3
}

// hasNoRestrictions returns true if the rule has no domain, GeoIP, client, or
// DNS restrictions.
//
// TODO(f.setrakov): Invert the condition.
func (r *NetworkRule) hasNoRestrictions() (ok bool) {
	return len(r.permittedDomains) == 0 &&
		len(r.restrictedDomains) == 0 &&
		r.permittedClients.len() == 0 &&
		r.restrictedClients.len() == 0 &&
		r.permittedClientTags.Len() == 0 &&
		r.restrictedClientTags.Len() == 0 &&
		len(r.permittedDNSTypes) == 0 &&
		len(r.restrictedDNSTypes) == 0 &&
		len(r.denyAllowDomains) == 0 &&
		!r.hasGeoIPRestrictions()
}

// hasGeoIPRestrictions returns true if the rule has ASN or Country
// restrictions.
func (r *NetworkRule) hasGeoIPRestrictions() (ok bool) {
	return r.restrictedASNs.Len() > 0 ||
		r.permittedASNs.Len() > 0 ||
		r.restrictedCountries.Len() > 0 ||
		r.permittedCountries.Len() > 0 ||
		r.unknownLocationPolicy != unknownLocationPolicyNone
}

// type check
var _ Rule = (*NetworkRule)(nil)

// Text implements the [Rule] interface for *NetworkRule.
func (r *NetworkRule) Text() (s string) {
	return r.text
}

// GetFilterListID implements the [Rule] interface for *NetworkRule.
func (r *NetworkRule) GetFilterListID() (id ListID) {
	return r.id
}

// String returns original rule text.
func (r *NetworkRule) String() (s string) {
	return r.text
}

// Match checks if this filtering rule matches the specified request.  req must
// not be nil.
func (r *NetworkRule) Match(req *Request) (ok bool) {
	switch {
	case
		!r.matchShortcut(req),
		r.IsOptionEnabled(OptionThirdParty) && !req.ThirdParty,
		r.IsOptionDisabled(OptionThirdParty) && req.ThirdParty,
		!r.matchRequestType(req.RequestType),
		!r.matchRequestDomain(req.Hostname, req.IsHostnameRequest),
		!r.matchSourceDomain(req.SourceHostname),
		!r.matchDNSType(req.DNSType),
		!r.matchClientTags(req.ClientTags),
		!r.matchClient(req.ClientIdentifiers, req.ClientIP),
		!r.matchPattern(req),
		!r.matchGeoIP(req.ClientASN, req.ClientCountry):
		return false
	}

	return true
}

// IsOptionEnabled returns true if the specified option is enabled.
func (r *NetworkRule) IsOptionEnabled(option NetworkRuleOption) (ok bool) {
	return (r.enabledOptions & option) == option
}

// IsOptionDisabled returns true if the specified option is disabled.
func (r *NetworkRule) IsOptionDisabled(option NetworkRuleOption) (ok bool) {
	return (r.disabledOptions & option) == option
}

// GetPermittedDomains returns the domains this rule is allowed on.
func (r *NetworkRule) GetPermittedDomains() (domains []string) {
	return r.permittedDomains
}

// IsHostLevelNetworkRule checks if this rule can be used for hosts-level
// blocking.
func (r *NetworkRule) IsHostLevelNetworkRule() (ok bool) {
	if len(r.permittedDomains) > 0 || len(r.restrictedDomains) > 0 {
		return false
	}

	if r.permittedRequestTypes != 0 && r.restrictedRequestTypes != 0 {
		return false
	}

	if r.disabledOptions != 0 {
		return false
	}

	if r.enabledOptions != 0 {
		return ((r.enabledOptions & OptionHostLevelRulesOnly) |
			(r.enabledOptions ^ OptionHostLevelRulesOnly)) == OptionHostLevelRulesOnly
	}

	return true
}

// isRegexPattern returns true if pattern may be treated as a regular expression
// rule.
func isRegexPattern(pattern string) (ok bool) {
	return len(pattern) > 1 && pattern[0] == '/' && pattern[len(pattern)-1] == '/'
}

// IsRegexRule returns true if the rule is a regular expression rule.
func (r *NetworkRule) IsRegexRule() (ok bool) {
	return isRegexPattern(r.pattern)
}

// IsGeneric returns true if the rule is considered generic.  A generic rule is
// not restricted to a set of domains.  Note that it might be forbidden on some
// domains, though.
func (r *NetworkRule) IsGeneric() (ok bool) {
	return len(r.permittedDomains) == 0
}

// IsHigherPriority checks if the rule has higher priority than the specified
// rule.  The priority rules are:
//  1. whitelist + $important;
//  2. $important;
//  3. whitelist;
//  4. basic rules.
func (r *NetworkRule) IsHigherPriority(other *NetworkRule) (ok bool) {
	// Check by $important criteria.
	if hasPriority, done := r.isHigherPriorityImportant(other); done {
		return hasPriority
	}

	// Check by whitelist criteria.
	if r.Whitelist && !other.Whitelist {
		return true
	}

	if other.Whitelist && !r.Whitelist {
		return false
	}

	// Compare basic rules.
	if r.IsOptionEnabled(OptionRedirect) && !other.IsOptionEnabled(OptionRedirect) {
		// $redirect rules have "slightly" higher priority than regular basic
		// rules.
		return true
	}

	if !r.IsGeneric() && other.IsGeneric() {
		// Specific rules have priority over generic rules.
		return true
	}

	return r.isHigherPrioritySpec(other)
}

// isHigherPriorityImportant compares rules with the $important modifier.
// Returns true if r has higher priority than the other.  done is true if the
// comparison is finished.  other must not be nil.
func (r *NetworkRule) isHigherPriorityImportant(other *NetworkRule) (ok, done bool) {
	important := r.IsOptionEnabled(OptionImportant)
	otherImportant := other.IsOptionEnabled(OptionImportant)

	switch {
	case r.isImportantWhitelist(other):
		return true, true
	case other.isImportantWhitelist(r):
		return false, true
	case important && !otherImportant:
		return true, true
	case otherImportant && !important:
		return false, true
	default:
		return false, false
	}
}

// isImportantWhitelist returns true if r is an important whitelist rule and
// other is a blocklist rule.  other must not be nil.
func (r *NetworkRule) isImportantWhitelist(other *NetworkRule) (ok bool) {
	return r.IsOptionEnabled(OptionImportant) && r.Whitelist && !other.Whitelist
}

// isHigherPrioritySpec compares the number of the rule's dedicated specifiers.
// More specific rules (i.e. with more modifiers) have higher priority.  Returns
// true if r has higher priority than the other.
func (r *NetworkRule) isHigherPrioritySpec(other *NetworkRule) (ok bool) {
	return r.calcRuleSpecs() > other.calcRuleSpecs()
}

// calcRuleSpecs returns the number of the rule's dedicated specifiers.  The
// number of the rule's specifiers is used to determine the rule's priority.
func (r *NetworkRule) calcRuleSpecs() (prio int) {
	return r.enabledOptions.Count() +
		r.disabledOptions.Count() +
		r.permittedRequestTypes.Count() +
		r.restrictedRequestTypes.Count() +
		mathutil.BoolToNumber[int](len(r.permittedDomains) != 0 || len(r.restrictedDomains) != 0) +
		mathutil.BoolToNumber[int](
			len(r.permittedDNSTypes) != 0 || len(r.restrictedDNSTypes) != 0,
		) +
		mathutil.BoolToNumber[int](
			r.permittedClientTags.Len() != 0 || r.restrictedClientTags.Len() != 0,
		) +
		mathutil.BoolToNumber[int](
			r.permittedClients.len() != 0 || r.restrictedClients.len() != 0,
		) +
		mathutil.BoolToNumber[int](len(r.denyAllowDomains) != 0) +
		mathutil.BoolToNumber[int](
			r.permittedASNs.Len() != 0 || r.restrictedASNs.Len() != 0 ||
				r.permittedCountries.Len() != 0 || r.restrictedCountries.Len() != 0 ||
				r.unknownLocationPolicy != unknownLocationPolicyNone,
		)
}

// negatesBadfilter only makes sense when r has a `badfilter` modifier.  It
// returns true if r negates other.
func (r *NetworkRule) negatesBadfilter(other *NetworkRule) (ok bool) {
	switch {
	case
		!r.IsOptionEnabled(OptionBadfilter),
		r.Whitelist != other.Whitelist,
		r.pattern != other.pattern,
		r.permittedRequestTypes != other.permittedRequestTypes,
		r.restrictedRequestTypes != other.restrictedRequestTypes,
		(r.enabledOptions ^ OptionBadfilter) != other.enabledOptions,
		r.disabledOptions != other.disabledOptions,
		!slices.Equal(r.permittedDomains, other.permittedDomains),
		!slices.Equal(r.restrictedDomains, other.restrictedDomains),
		!r.permittedClientTags.Equal(other.permittedClientTags),
		!r.restrictedClientTags.Equal(other.restrictedClientTags),
		!r.permittedClients.equal(other.permittedClients),
		!r.restrictedClients.equal(other.restrictedClients),
		!r.permittedASNs.Equal(other.permittedASNs),
		!r.restrictedASNs.Equal(other.restrictedASNs),
		!r.permittedCountries.Equal(other.permittedCountries),
		!r.restrictedCountries.Equal(other.restrictedCountries),
		r.unknownLocationPolicy != other.unknownLocationPolicy:
		return false
	}

	return true
}

// isDocumentWhitelistRule checks if the rule is a document-level whitelist rule.  This
// means that the rule is supposed to disable or modify blocking of the page
// subrequests.  For example, "@@||example.org^$urlblock" unblocks all
// sub-requests.
func (r *NetworkRule) isDocumentWhitelistRule() (ok bool) {
	return r.Whitelist &&
		(r.IsOptionEnabled(OptionUrlblock) || r.IsOptionEnabled(OptionGenericblock))
}

// preparePattern converts the pattern to a regexp and parses it.  It should be
// called before matching the rule by pattern.  It sets either matchesNothing,
// matchesAll, or regex.
func (r *NetworkRule) preparePattern() {
	if r.matchesNothing {
		return
	}

	// It is important to set r.matchesNothing to true until proven otherwise to
	// prevent panics in r.matchPattern in case of panics anywere below.
	r.matchesNothing = true

	pattern := patternToRegexp(r.pattern)
	if pattern == RegexAnyCharacter {
		r.matchesAll = true
	}

	if !r.IsOptionEnabled(OptionMatchCase) {
		pattern = "(?i)" + pattern
	}

	// TODO(a.garipov):  Consider ways to log the error.  Perhaps, a logger from
	// a context?
	var err error
	r.regexp, err = regexp.Compile(pattern)
	r.matchesNothing = err != nil
}

// matchPattern uses the regex pattern to match the request URL.  req must not
// be nil.
func (r *NetworkRule) matchPattern(req *Request) (matched bool) {
	r.initOnce.Do(r.preparePattern)
	if r.matchesNothing {
		return false
	} else if r.matchesAll {
		return true
	}

	if r.shouldMatchHostname(req) {
		return r.regexp.MatchString(req.Hostname)
	}

	return r.regexp.MatchString(req.URL)
}

// shouldMatchHostname checks if we should match hostname and not the URL.  This
// is important for DNS-level blocking.
//
// NOTE:  Full URL matching should be performed in some cases, see
// https://github.com/AdguardTeam/AdGuardHome/issues/1249.
func (r *NetworkRule) shouldMatchHostname(req *Request) (ok bool) {
	if !req.IsHostnameRequest {
		return false
	}

	if r.hasURLPrefix() {
		return false
	}

	// Patterns that start with '/' and end with '.' are treated as
	// URL-specific ones.
	return len(r.pattern) < minPatternLen ||
		r.pattern[0] != '/' ||
		r.pattern[len(r.pattern)-1] != '.'
}

// hasURLPrefix reports whether the rule pattern starts with a URL-specific
// prefix.
func (r *NetworkRule) hasURLPrefix() (ok bool) {
	return strings.HasPrefix(r.pattern, MaskStartURL) ||
		strings.HasPrefix(r.pattern, "http://") ||
		strings.HasPrefix(r.pattern, "https://") ||
		strings.HasPrefix(r.pattern, "://")
}

// matchShortcut simply checks if shortcut is a substring of the URL.
func (r *NetworkRule) matchShortcut(req *Request) (ok bool) {
	return strings.Contains(req.URLLowerCase, r.Shortcut)
}

// matchRequestDomain checks if the filtering rule is allowed to match this
// request domain, e.g. it checks it against the $denyallow modifier.
//
// NOTE:  The rule will work if the request hostname DOES NOT belong to
// $denyallow domains.  The idea is to allow rules that block anything EXCEPT
// for some domains.  For example, if there is a website that loads a lot of
// third-party trackers, but some of the domains are crucial for this website,
// something like this can be used:
//
//	"*$script,domain=example.org,denyallow=essential1.com|essential2.com"
func (r *NetworkRule) matchRequestDomain(domain string, hostnameRequest bool) (ok bool) {
	if len(r.denyAllowDomains) == 0 {
		return true
	}

	// If this is a hostname request, it's likely DNS-level filtering.  Avoid
	// matching IP addresses here since they can only come from CNAME filtering,
	// so regardless of whether it actually matches the "denyallow" list,
	// consider that it does not.
	//
	// See: https://github.com/AdguardTeam/AdGuardHome/issues/3175.
	if hostnameRequest && netutil.IsValidIPString(domain) {
		return false
	}

	return !isDomainOrSubdomainOfAny(domain, r.denyAllowDomains)
}

// matchSourceDomain checks if the specified filtering rule is allowed on this
// domain.  That is, it checks the domain against what's specified in the
// $domain modifier.
func (r *NetworkRule) matchSourceDomain(domain string) (ok bool) {
	if len(r.permittedDomains) == 0 && len(r.restrictedDomains) == 0 {
		return true
	}

	if len(r.restrictedDomains) > 0 {
		if isDomainOrSubdomainOfAny(domain, r.restrictedDomains) {
			// Domain or host is restricted, i.e. $domain=~example.org.
			return false
		}
	}

	if len(r.permittedDomains) > 0 {
		if !isDomainOrSubdomainOfAny(domain, r.permittedDomains) {
			// Domain is not among permitted, i.e. $domain=example.org and we're
			// checking example.com.
			return false
		}
	}

	return true
}

// matchDNSType checks if the specified filtering rule is allowed for this DNS
// request record type.
func (r *NetworkRule) matchDNSType(rtype uint16) (allowed bool) {
	if len(r.permittedDNSTypes) == 0 && len(r.restrictedDNSTypes) == 0 {
		return true
	}

	if slices.Contains(r.restrictedDNSTypes, rtype) {
		return false
	}

	if len(r.permittedDNSTypes) > 0 {
		return slices.Contains(r.permittedDNSTypes, rtype)
	}

	return true
}

// matchClientTags returns true if r matches one of tags.
func (r *NetworkRule) matchClientTags(tags *container.SortedSliceSet[string]) (ok bool) {
	if r.restrictedClientTags.Len() == 0 && r.permittedClientTags.Len() == 0 {
		// the rule doesn't contain $ctag extension
		return true
	}

	if r.restrictedClientTags.Intersects(tags) {
		// matched by restricted client tag
		return false
	}

	if r.permittedClientTags.Len() != 0 {
		// If the rule is permitted for specific tags only,
		// we should check whether our tag is among permitted or not
		// and return the result the result immediately
		return r.permittedClientTags.Intersects(tags)
	}

	return true
}

// matchClient returns true if the rule is specified for client defined by
// host or ip.
func (r *NetworkRule) matchClient(ids *container.SortedSliceSet[string], ip netip.Addr) (ok bool) {
	restLen := r.restrictedClients.len()
	permLen := r.permittedClients.len()

	if restLen == 0 && permLen == 0 {
		// The rule has no $client modifier.
		return true
	}

	if r.restrictedClients.match(ids, ip) {
		// The client is in the restricted set.
		return false
	}

	if permLen != 0 {
		// If the rule is permitted for specific client only, check whether the
		// client is among permitted.
		return r.permittedClients.match(ids, ip)
	}

	// If we got here, permitted list is empty and the client is not among
	// restricted.
	return true
}

// matchGeoIP returns true if r matches geoip data.
func (r *NetworkRule) matchGeoIP(asn geoip.ASN, country geoip.Country) (ok bool) {
	if r.unknownLocationPolicy != unknownLocationPolicyNone {
		return r.matchUnknownLocationRestriction(asn, country)
	}

	if !r.hasGeoIPRestrictions() {
		return true
	}

	if r.restrictedASNs.Has(asn) || countriesHasFold(r.restrictedCountries, country) {
		return false
	}

	asnPermLen := r.permittedASNs.Len()
	countryPermLen := r.permittedCountries.Len()
	if asnPermLen == 0 && countryPermLen == 0 {
		return true
	} else if asnPermLen == 0 {
		return countriesHasFold(r.permittedCountries, country)
	} else if countryPermLen == 0 {
		return r.permittedASNs.Has(asn)
	}

	return r.permittedCountries.Has(country) || r.permittedASNs.Has(asn)
}

// countriesHasFold returns true if the set contains the country, using
// case-insensitive comparison.
func countriesHasFold(
	set *container.SortedSliceSet[geoip.Country],
	country geoip.Country,
) (ok bool) {
	values := set.Values()

	_, ok = slices.BinarySearchFunc(values, country, func(a, b string) (res int) {
		if strings.EqualFold(a, b) {
			return 0
		}

		return strings.Compare(a, b)
	})

	return ok
}

// matchUnknownLocationRestriction returns true if given asn and country match
// r's unknown location restriction.
func (r *NetworkRule) matchUnknownLocationRestriction(
	asn geoip.ASN,
	country geoip.Country,
) (ok bool) {
	hasLocation := asn != geoip.ASNUnknown || country != geoip.CountryUnknown
	if hasLocation {
		return r.unknownLocationPolicy == unknownLocationPolicyRestrict
	}

	return r.unknownLocationPolicy == unknownLocationPolicyPermit
}

// matchRequestType returns true if rt matches the rule properties.
func (r *NetworkRule) matchRequestType(rt RequestType) (ok bool) {
	if r.permittedRequestTypes != 0 {
		if (r.permittedRequestTypes & rt) != rt {
			return false
		}
	}

	if r.restrictedRequestTypes != 0 {
		if (r.restrictedRequestTypes & rt) == rt {
			return false
		}
	}

	return true
}

// setOptionEnabled enables or disables the specified option.  It returns an
// error if option cannot be used with this type of rules.
func (r *NetworkRule) setOptionEnabled(option NetworkRuleOption, enabled bool) (err error) {
	if r.Whitelist && (option&OptionBlacklistOnly) == option {
		return fmt.Errorf("modifier cannot be used in whitelist rules: %v", option)
	}

	if !r.Whitelist && (option&OptionWhitelistOnly) == option {
		return fmt.Errorf("modifier cannot be used in blacklist rules: %v", option)
	}

	if enabled {
		r.enabledOptions |= option
	} else {
		r.disabledOptions |= option
	}

	return nil
}

// loadOptions parses and adds all options from optStr to r.
//
// See https://adguard.com/kb/general/ad-filtering/create-own-filters/#basic-rules.
func (r *NetworkRule) loadOptions(optStr string) (err error) {
	if optStr == "" {
		return nil
	}

	for _, o := range splitWithEscapeCharacter(optStr, ',', '\\') {
		if eqIdx := strings.IndexByte(o, '='); eqIdx > 0 {
			err = r.setOption(o[:eqIdx], o[eqIdx+1:])
		} else {
			err = r.setOption(o, "")
		}
		if err != nil {
			return err
		}
	}

	switch {
	case
		r.IsOptionEnabled(OptionJsinject),
		r.IsOptionEnabled(OptionElemhide),
		r.IsOptionEnabled(OptionContent),
		r.IsOptionEnabled(OptionUrlblock),
		r.IsOptionEnabled(OptionGenericblock),
		r.IsOptionEnabled(OptionGenerichide),
		r.IsOptionEnabled(OptionExtension),
		r.IsOptionEnabled(OptionPopup):
		// Rules of these types can be applied to documents only.
		r.permittedRequestTypes = TypeDocument
	default:
		// Go on.
	}

	return nil
}

// optionHandler is used to set specific option for *NetworkRule.
type optionHandler func(r *NetworkRule, value string) (err error)

// optionHandlers is used for mapping option names to their handlers.
var optionHandlers = map[string]optionHandler{
	// General options.
	"third-party":  newSetOptionEnabledHandler(OptionThirdParty, true),
	"~first-party": newSetOptionEnabledHandler(OptionThirdParty, true),
	"~third-party": newSetOptionEnabledHandler(OptionThirdParty, false),
	"first-party":  newSetOptionEnabledHandler(OptionThirdParty, false),
	"match-case":   newSetOptionEnabledHandler(OptionMatchCase, true),
	"~match-case":  newSetOptionEnabledHandler(OptionMatchCase, false),
	"important":    newSetOptionEnabledHandler(OptionImportant, true),
	"badfilter":    newSetOptionEnabledHandler(OptionBadfilter, true),
	// Document-level whitelist rules.
	"elemhide":     newSetOptionEnabledHandler(OptionElemhide, true),
	"generichide":  newSetOptionEnabledHandler(OptionGenerichide, true),
	"genericblock": newSetOptionEnabledHandler(OptionGenericblock, true),
	"jsinject":     newSetOptionEnabledHandler(OptionJsinject, true),
	"urlblock":     newSetOptionEnabledHandler(OptionUrlblock, true),
	"content":      newSetOptionEnabledHandler(OptionContent, true),
	// Stealth mode.
	"stealth": newSetOptionEnabledHandler(OptionStealth, true),
	// $popup blocking options.
	"popup": newSetOptionEnabledHandler(OptionPopup, true),
	// $empty and $mp4.
	// TODO(ameshkov):  Deprecate in favor of $redirect.
	"empty": newSetOptionEnabledHandler(OptionEmpty, true),
	"mp4":   newSetOptionEnabledHandler(OptionMp4, true),
	// Content type options.
	"script":          newSetRequestTypeHandler(TypeScript, true),
	"~script":         newSetRequestTypeHandler(TypeScript, false),
	"stylesheet":      newSetRequestTypeHandler(TypeStylesheet, true),
	"~stylesheet":     newSetRequestTypeHandler(TypeStylesheet, false),
	"subdocument":     newSetRequestTypeHandler(TypeSubdocument, true),
	"~subdocument":    newSetRequestTypeHandler(TypeSubdocument, false),
	"object":          newSetRequestTypeHandler(TypeObject, true),
	"~object":         newSetRequestTypeHandler(TypeObject, false),
	"image":           newSetRequestTypeHandler(TypeImage, true),
	"~image":          newSetRequestTypeHandler(TypeImage, false),
	"xmlhttprequest":  newSetRequestTypeHandler(TypeXmlhttprequest, true),
	"~xmlhttprequest": newSetRequestTypeHandler(TypeXmlhttprequest, false),
	"media":           newSetRequestTypeHandler(TypeMedia, true),
	"~media":          newSetRequestTypeHandler(TypeMedia, false),
	"font":            newSetRequestTypeHandler(TypeFont, true),
	"~font":           newSetRequestTypeHandler(TypeFont, false),
	"websocket":       newSetRequestTypeHandler(TypeWebsocket, true),
	"~websocket":      newSetRequestTypeHandler(TypeWebsocket, false),
	"ping":            newSetRequestTypeHandler(TypePing, true),
	"~ping":           newSetRequestTypeHandler(TypePing, false),
	"other":           newSetRequestTypeHandler(TypeOther, true),
	"~other":          newSetRequestTypeHandler(TypeOther, false),
	// $extension can be also disabled.
	"extension": newSetOptionEnabledHandler(OptionExtension, true),
	"~extension": func(r *NetworkRule, _ string) (err error) {
		r.enabledOptions = r.enabledOptions ^ OptionExtension

		return nil
	},
	// $dnstype, the DNS request record type filter.
	"dnstype": setDNSTypeOptionHandler,
	// $dnsrewrite, the DNS request rewrite filter.
	"dnsrewrite": setDNSRewriteOptionHandler,
	// $domain limits the rule for selected source domains.
	"domain": setDomainOptionHandler,
	// $denyallow disables the rule for the selected request domains.
	"denyallow": setDenyAllowOptionHandler,
	"ctag":      setCTagOptionHandler,
	"client":    setClientOptionHandler,
	// $document.
	"document": setDocumentOptionHandler,
	// $respgeo
	"respgeo": setRespGeoOptionHandler,
}

// newSetRequestTypeHandler returns new [optionHandler] that permits or forbids
// the specified request type.
func newSetRequestTypeHandler(requestType RequestType, permitted bool) (handler optionHandler) {
	return func(r *NetworkRule, _ string) (err error) {
		if permitted {
			r.permittedRequestTypes |= requestType
		} else {
			r.restrictedRequestTypes |= requestType
		}

		return nil
	}
}

// newSetOptionEnabledHandler returns new [optionHandler] that enables or
// disables the specified option.  It returns an error if option cannot be used
// with this type of rules.
func newSetOptionEnabledHandler(option NetworkRuleOption, enabled bool) (handler optionHandler) {
	return func(r *NetworkRule, _ string) (err error) {
		return r.setOptionEnabled(option, enabled)
	}
}

// setDNSTypeOptionHandler is an [optionHandler] that parses dnstype option
// value and sets permitted and restricted dns types.  r must not be nil.
func setDNSTypeOptionHandler(r *NetworkRule, value string) (err error) {
	permitted, restricted, err := parseDNSTypes(value)
	r.permittedDNSTypes = permitted
	r.restrictedDNSTypes = restricted

	// Don't wrap the error, because it's informative enough as is.
	return err
}

// setDNSRewriteOptionHandler is an [optionHandler] that parses dnsrewrite value
// and fills [NetworkRule.DNSRewrite].  r must not be nil.
func setDNSRewriteOptionHandler(r *NetworkRule, value string) (err error) {
	// $dnsrewrite, the DNS request rewrite filter.
	rewrite, err := parseDNSRewrite(value)
	r.DNSRewrite = rewrite

	// Don't wrap the error, because it's informative enough as is.
	return err
}

// setDomainOptionHandler is an [optionHandler] that parses domains and sets
// permitted and restricted domains.  r must not be nil.
func setDomainOptionHandler(r *NetworkRule, value string) (err error) {
	permitted, restricted, err := parseDomains(value, "|")
	r.permittedDomains = permitted
	r.restrictedDomains = restricted

	// Don't wrap the error, because it's informative enough as is.
	return err
}

// setDenyallowOptionHandler is an [optionHandler] that parses domains and sets
// [NetworkRule.denyAllowDomains].  r must not be nil.
func setDenyAllowOptionHandler(r *NetworkRule, value string) (err error) {
	permitted, restricted, err := parseDomains(value, "|")
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	if len(restricted) > 0 || len(permitted) == 0 {
		return fmt.Errorf("invalid $denyallow value: %q", value)
	}

	r.denyAllowDomains = permitted

	return nil
}

// setCtagOptionHandler is an [optionHandler] that parses CTags from value and
// sets permitted and restricted client tags.  r must not be nil.
func setCTagOptionHandler(r *NetworkRule, value string) (err error) {
	permitted, restricted, err := parseCTags(value, "|")
	if err == nil {
		r.permittedClientTags = permitted
		r.restrictedClientTags = restricted
	}

	// Don't wrap the error, because it's informative enough as is.
	return err
}

// setClientOptionHandler is an [optionHandler] that parses clients from value
// and sets permitted and restricted clients.  r must not be nil.
func setClientOptionHandler(r *NetworkRule, value string) (err error) {
	permitted, restricted, err := parseClients(value, '|')
	if err == nil {
		r.permittedClients = permitted
		r.restrictedClients = restricted
	}

	// Don't wrap the error, because it's informative enough as is.
	return err
}

// setDocumentOptionHandler is an [optionHandler] that enables such options as
// jsinject, urlblock, content and extension.  r must not be nil.
func setDocumentOptionHandler(r *NetworkRule, _ string) (err error) {
	err = r.setOptionEnabled(OptionElemhide, true)
	// Ignore others.
	_ = r.setOptionEnabled(OptionJsinject, true)
	_ = r.setOptionEnabled(OptionUrlblock, true)
	_ = r.setOptionEnabled(OptionContent, true)
	_ = r.setOptionEnabled(OptionExtension, true)

	// Don't wrap the error, because it's informative enough as is.
	return err
}

// setRespGeoOptionHandler is an [optionHandler] that parses respgeo option
// value and sets allowed ASNs and countries.  r must not be nil.
func setRespGeoOptionHandler(r *NetworkRule, value string) (err error) {
	err = parseGeoIP(r, value, "|")

	// Don't wrap the error, because it's informative enough as is.
	return err
}

// setOption sets the specified option with its optional value.
func (r *NetworkRule) setOption(name, value string) (err error) {
	handler, ok := optionHandlers[name]
	if ok {
		return handler(r, value)
	}

	return fmt.Errorf("unknown filter modifier: %q=%q", name, value)
}

// setShortcut extracts a shortcut from the pattern and sets it in r.  A
// shortcut is the longest substring of the pattern that does not contain any
// special characters.
//
// TODO(a.garipov):  Test and optimize to not call strings.ToLower.
func (r *NetworkRule) setShortcut() {
	var shortcut string
	if r.IsRegexRule() {
		shortcut = findRegexpShortcut(r.pattern)
	} else {
		shortcut = findShortcut(r.pattern)
	}

	// A shortcut needs to be at least longer than 1 character.
	if len(shortcut) > 1 {
		r.Shortcut = strings.ToLower(shortcut)
	}
}

// findShortcut searches for the longest substring of the pattern that does not
// contain any of the special characters, which are '*', '^', and '|'.
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

// findRegexpShortcut searches for a shortcut inside of a regexp pattern.  A
// shortcut in this case is a longest string with no regexp special characters.
// It also discards complicated regexps right away.
//
// TODO(a.garipov):  This requires a deep refactoring and optimization.
func findRegexpShortcut(pattern string) (shortcut string) {
	// Strip backslashes.
	pattern = pattern[1 : len(pattern)-1]

	if strings.Contains(pattern, "?") {
		// Do not mess with complex expressions which use lookahead.
		//
		// See https://github.com/AdguardTeam/AdguardBrowserExtension/issues/978.
		//
		// TODO(a.garipov):  Reinspect.
		return ""
	}

	// placeholder for a special character
	specialCharacter := "..."

	// (Dirty) prepend specialCharacter for the following replace calls to work properly
	pattern = specialCharacter + pattern

	// Strip all types of brackets.
	pattern = regexpBracketsCurly.ReplaceAllString(pattern, "$1"+specialCharacter)
	pattern = regexpBracketsRound.ReplaceAllString(pattern, "$1"+specialCharacter)
	pattern = regexpBracketsSquare.ReplaceAllString(pattern, "$1"+specialCharacter)

	// Strip some escaped characters.
	pattern = regexpEscapedCharacters.ReplaceAllString(pattern, "$1"+specialCharacter)

	// Split by special characters.
	parts := regexpSpecialCharacters.Split(pattern, -1)
	longest := ""
	for _, part := range parts {
		if len(part) > len(longest) {
			longest = part
		}
	}

	return longest
}

// parseRuleText splits the rule's text into pattern, which is a basic rule
// pattern that can be easily converted into a regular expression, and options,
// a string containing the rule's options.  isWhitelist is true if the rule
// should unblock requests instead of blocking them.
func parseRuleText(ruleText string) (pattern, options string, isWhitelist bool, err error) {
	if ruleText == "" || ruleText == maskWhiteList {
		return "", "", isWhitelist, fmt.Errorf("rule %q is too short", ruleText)
	}

	ruleText, isWhitelist = stripWhitelistPrefix(ruleText)

	if isRegexRuleWithoutOptions(ruleText) {
		return ruleText, "", isWhitelist, nil
	}

	pattern, options = splitPatternAndOptions(ruleText)

	return pattern, options, isWhitelist, nil
}

// stripWhitelistPrefix removes whitelist prefix and returns whether rule is
// whitelist.
func stripWhitelistPrefix(ruleText string) (stripped string, isWhitelist bool) {
	if strings.HasPrefix(ruleText, maskWhiteList) {
		return ruleText[len(maskWhiteList):], true
	}

	return ruleText, false
}

// isRegexRuleWithoutOptions checks if rule is a regex rule without options.
//
// TODO(f.setrakov): Remove allocation.
func isRegexRuleWithoutOptions(ruleText string) (ok bool) {
	return strings.HasPrefix(ruleText, maskRegexRule) &&
		strings.HasSuffix(ruleText, maskRegexRule) &&
		!strings.Contains(ruleText, replaceOption+"=")
}

// splitPatternAndOptions splits rule text into pattern and options parts.
func splitPatternAndOptions(ruleText string) (pattern, options string) {
	idx, hasEscaped := findOptionsDelimiter(ruleText)
	if idx == -1 {
		return ruleText, ""
	}

	pattern, options = ruleText[:idx], ruleText[idx+1:]
	if hasEscaped {
		options = regexpEscapedOptionsDelimiter.ReplaceAllString(
			options,
			string(optionsDelimiter),
		)
	}

	return pattern, options
}

// findOptionsDelimiter finds the position of options delimiter and whether it
// has escaped delimiters.
func findOptionsDelimiter(ruleText string) (idx int, hasEscaped bool) {
	for idx = len(ruleText) - 1; idx >= 0; idx-- {
		if ruleText[idx] != optionsDelimiter {
			continue
		}

		if idx > 0 && ruleText[idx-1] == escapeCharacter {
			hasEscaped = true

			continue
		}

		return idx, hasEscaped
	}

	return -1, hasEscaped
}
