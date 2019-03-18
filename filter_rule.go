package urlfilter

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

const (
	maskWhiteList    = "@@"
	maskRegexRule    = "/"
	replaceOption    = "replace"
	optionsDelimiter = '$'
	escapeCharacter  = '\\'
)

var (
	reEscapedOptionsDelimiter, _ = regexp.Compile(regexp.QuoteMeta("\\$"))
)

// FilterRuleOption is the enumeration of various rule options
// In order to save memory, we store some options as a flag
type FilterRuleOption uint

// FilterRuleOption enumeration
const (
	OptionThirdParty FilterRuleOption = 1 << iota // $third-party modifier
	OptionMatchCase                               // $match-case modifier

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

	// Content-modifying
	OptionEmpty // $empty
	OptionMp4   // $mp4

	// Blocking
	OptionPopup // $popup

	// TypeOther
	OptionCsp     // $csp
	OptionReplace // $replace
	OptionCookie  // $cookie
)

// FilterRule is a basic filtering rule
// https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters#basic-rules
type FilterRule struct {
	RuleText  string // RuleText is the original rule text
	Whitelist bool   // true if this is an exception rule

	enabledOptions  FilterRuleOption // Flag with all enabled rule options
	disabledOptions FilterRuleOption // Flag with all disabled rule options

	permittedRequestTypes  RequestType // Flag with all permitted request types. 0 means ALL.
	restrictedRequestTypes RequestType // Flag with all restricted request types. 0 means NONE.

	pattern string         // Pattern is the basic rule pattern ready to be compiled to regex
	regex   *regexp.Regexp // Regex is the regular expression compiled from the regex
	invalid bool           // Marker that the rule is invalid. Match will always return false in this case

	sync.Mutex
}

// NewFilterRule parses the rule text and returns a filter rule
func NewFilterRule(ruleText string) (*FilterRule, error) {
	pattern, options, whitelist, err := parseRuleText(ruleText)

	if err != nil {
		return nil, err
	}

	// TODO: Parse options

	rule := FilterRule{
		RuleText:  ruleText,
		Whitelist: whitelist,
		pattern:   pattern,
	}

	err = rule.loadOptions(options)
	if err != nil {
		return nil, err
	}

	return &rule, nil
}

// Match checks if this filtering rule matches the specified request
func (f *FilterRule) Match(r *Request) bool {
	if f.isOptionEnabled(OptionThirdParty) && !r.ThirdParty {
		return false
	}

	if f.isOptionDisabled(OptionThirdParty) && r.ThirdParty {
		return false
	}

	if !f.matchRequestType(r.RequestType) {
		return false
	}

	return f.matchPattern(r)
}

// matchPattern uses the regex pattern to match the request URL
func (f *FilterRule) matchPattern(r *Request) bool {
	f.Lock()
	if f.regex == nil {
		if f.invalid {
			f.Unlock()
			return false
		}

		pattern := patternToRegexp(f.pattern)
		if !f.isOptionEnabled(OptionMatchCase) {
			pattern = "(?i)" + pattern
		}

		re, err := regexp.Compile(pattern)
		if err != nil {
			f.invalid = true
			f.Unlock()
			return false
		}
		f.regex = re
	}
	f.Unlock()
	return f.regex.MatchString(r.URL)
}

// matchRequestType checks if the specified request type matches the rule properties
func (f *FilterRule) matchRequestType(requestType RequestType) bool {
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
func (f *FilterRule) setRequestType(requestType RequestType, permitted bool) {
	if permitted {
		f.permittedRequestTypes |= requestType
	} else {
		f.restrictedRequestTypes |= requestType
	}
}

// isOptionEnabled returns true if the specified option is enabled
func (f *FilterRule) isOptionEnabled(option FilterRuleOption) bool {
	return (f.enabledOptions & option) == option
}

// isOptionDisabled returns true if the specified option is disabled
func (f *FilterRule) isOptionDisabled(option FilterRuleOption) bool {
	return (f.disabledOptions & option) == option
}

// enableOption enables or disables the specified option
// it can return error if this option cannot be used with this type of rules
func (f *FilterRule) setOptionEnabled(option FilterRuleOption, enabled bool) error {
	// TODO: Add whitelist/blacklist check

	if enabled {
		f.enabledOptions |= option
	} else {
		f.disabledOptions |= option
	}

	return nil
}

// loadOptions loads all the filtering rule options
// read the details on each here: https://kb.adguard.com/en/general/how-to-create-your-own-ad-filters#basic-rules
func (f *FilterRule) loadOptions(options string) error {
	if options == "" {
		return nil
	}

	optionsParts := splitWithEscapeCharacter(options, ',', '\\', false)
	for i := 0; i < len(optionsParts); i++ {
		option := optionsParts[i]
		valueIndex := strings.Index(option, "=")
		optionName := option
		optionValue := ""
		if valueIndex > 0 {
			optionName = option[:valueIndex]
			optionValue = option[valueIndex+1:]
		}

		err := f.loadOption(optionName, optionValue)
		if err != nil {
			return err
		}
	}

	return nil
}

// loadOption loads specified option with its value (optional)
// nolint:gocyclo
func (f *FilterRule) loadOption(name string, value string) error {
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

	// Content type options
	case "script":
		f.setRequestType(TypeScript, true)
		return nil
	case "~script":
		f.setRequestType(TypeScript, false)
		return nil
	case "stylesheet":
		f.setRequestType(TypeStylesheet, true)
		return nil
	case "~stylesheet":
		f.setRequestType(TypeStylesheet, false)
		return nil
	case "subdocument":
		f.setRequestType(TypeSubdocument, true)
		return nil
	case "~subdocument":
		f.setRequestType(TypeSubdocument, false)
		return nil
	case "object":
		f.setRequestType(TypeObject, true)
		return nil
	case "~object":
		f.setRequestType(TypeObject, false)
		return nil
	case "image":
		f.setRequestType(TypeImage, true)
		return nil
	case "~image":
		f.setRequestType(TypeImage, false)
		return nil
	case "xmlhttprequest":
		f.setRequestType(TypeXmlhttprequest, true)
		return nil
	case "~xmlhttprequest":
		f.setRequestType(TypeXmlhttprequest, false)
		return nil
	case "object-subrequest":
		f.setRequestType(TypeObjectSubrequest, true)
		return nil
	case "~object-subrequest":
		f.setRequestType(TypeObjectSubrequest, false)
		return nil
	case "media":
		f.setRequestType(TypeMedia, true)
		return nil
	case "~media":
		f.setRequestType(TypeMedia, false)
		return nil
	case "font":
		f.setRequestType(TypeFont, true)
		return nil
	case "~font":
		f.setRequestType(TypeFont, false)
		return nil
	case "websocket":
		f.setRequestType(TypeWebsocket, true)
		return nil
	case "~websocket":
		f.setRequestType(TypeWebsocket, false)
		return nil
	case "other":
		f.setRequestType(TypeOther, true)
		return nil
	case "~other":
		f.setRequestType(TypeOther, false)
		return nil
	}

	return fmt.Errorf("unknown filter modifier: %s=%s", name, value)
}

// parseRuleText splits the rule text in multiple parts:
// pattern -- a basic rule pattern (which can be easily converted into a regex)
// options -- a string with all rule options
// whitelist -- indicates if rule is "whitelist" (e.g. it should unblock requests, not block them)
func parseRuleText(ruleText string) (pattern string, options string, whitelist bool, err error) {
	startIndex := 0
	if strings.HasPrefix(ruleText, maskWhiteList) {
		whitelist = true
		startIndex = len(maskWhiteList)
	}

	if len(ruleText) <= startIndex {
		err = fmt.Errorf("the rule is too short: %s", ruleText)
		return
	}

	// Avoid parsing options inside of a regex rule
	if strings.HasPrefix(ruleText, maskRegexRule) &&
		strings.HasSuffix(ruleText, maskRegexRule) &&
		!strings.Contains(ruleText, replaceOption+"=") {
		pattern = ruleText
		return
	}

	// Setting pattern to rule text (for the case of empty options)
	pattern = ruleText[startIndex:]

	foundEscaped := false
	for i := len(ruleText) - 2; i >= startIndex; i-- {
		c := ruleText[i]

		if c == optionsDelimiter {
			if i > startIndex && ruleText[i-1] == escapeCharacter {
				foundEscaped = true
			} else {
				pattern = ruleText[startIndex:i]
				options = ruleText[i+1:]

				if foundEscaped {
					options = reEscapedOptionsDelimiter.ReplaceAllString(options, string(optionsDelimiter))
				}

				// Options delimiter was found, exiting loop
				break
			}
		}
	}

	return
}
