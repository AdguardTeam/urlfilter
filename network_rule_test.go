package urlfilter

import (
	"bytes"
	"log"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseNetworkRuleText(t *testing.T) {
	pattern, options, whitelist, err := parseRuleText("||example.org^")
	assert.Equal(t, "||example.org^", pattern)
	assert.Equal(t, "", options)
	assert.Equal(t, false, whitelist)
	assert.Nil(t, err)

	pattern, options, whitelist, err = parseRuleText("||example.org^$third-party")
	assert.Equal(t, "||example.org^", pattern)
	assert.Equal(t, "third-party", options)
	assert.Equal(t, false, whitelist)
	assert.Nil(t, err)

	pattern, options, whitelist, err = parseRuleText("@@||example.org^$third-party")
	assert.Equal(t, "||example.org^", pattern)
	assert.Equal(t, "third-party", options)
	assert.Equal(t, true, whitelist)
	assert.Nil(t, err)

	pattern, options, whitelist, err = parseRuleText("@@||example.org/this$is$path$third-party")
	assert.Equal(t, "||example.org/this$is$path", pattern)
	assert.Equal(t, "third-party", options)
	assert.Equal(t, true, whitelist)
	assert.Nil(t, err)

	pattern, options, whitelist, err = parseRuleText("@@||example.org/this$is$path$third-party")
	assert.Equal(t, "||example.org/this$is$path", pattern)
	assert.Equal(t, "third-party", options)
	assert.Equal(t, true, whitelist)
	assert.Nil(t, err)

	pattern, options, whitelist, err = parseRuleText("/regex/")
	assert.Equal(t, "/regex/", pattern)
	assert.Equal(t, "", options)
	assert.Equal(t, false, whitelist)
	assert.Nil(t, err)

	pattern, options, whitelist, err = parseRuleText("@@/regex/")
	assert.Equal(t, "/regex/", pattern)
	assert.Equal(t, "", options)
	assert.Equal(t, true, whitelist)
	assert.Nil(t, err)

	pattern, options, whitelist, err = parseRuleText("@@/regex/$replace=/test/test2/")
	assert.Equal(t, "/regex/", pattern)
	assert.Equal(t, "replace=/test/test2/", options)
	assert.Equal(t, true, whitelist)
	assert.Nil(t, err)
}

func TestFindShortcut(t *testing.T) {
	shortcut := findShortcut("||example.org^")
	assert.Equal(t, "example.org", shortcut)

	shortcut = findShortcut("|https://*examp")
	assert.Equal(t, "https://", shortcut)

	shortcut = findRegexpShortcut("/example/")
	assert.Equal(t, "example", shortcut)

	shortcut = findRegexpShortcut("/^http:\\/\\/example/")
	assert.Equal(t, "/example", shortcut)

	shortcut = findRegexpShortcut("/^http:\\/\\/[a-z]+\\.example/")
	assert.Equal(t, "example", shortcut)
}

func TestSimpleBasicRules(t *testing.T) {
	// Simple matching rule
	f, err := NewNetworkRule("||example.org^", 0)
	r := NewRequest("https://example.org/", "", TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	// Simple regex rule
	f, err = NewNetworkRule("/example\\.org/", 0)
	r = NewRequest("https://example.org/", "", TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))
}

func TestUnknownModifier(t *testing.T) {
	_, err := NewNetworkRule("||example.org^$unknown", 0)
	assert.NotNil(t, err)
}

func TestMatchCase(t *testing.T) {
	f, err := NewNetworkRule("||example.org^$match-case", 0)
	r := NewRequest("https://example.org/", "", TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = NewRequest("https://EXAMPLE.org/", "", TypeOther)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))
}

func TestThirdParty(t *testing.T) {
	f, err := NewNetworkRule("||example.org^$third-party", 0)

	// First-party 1
	r := NewRequest("https://example.org/", "", TypeOther)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	// First-party 2
	r = NewRequest("https://sub.example.org/", "https://example.org/", TypeOther)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	// Third-party
	r = NewRequest("https://example.org/", "https://example.com", TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	f, err = NewNetworkRule("||example.org^$first-party", 0)

	// First-party 1
	r = NewRequest("https://example.org/", "", TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	// First-party
	r = NewRequest("https://sub.example.org/", "https://example.org/", TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	// Third-party
	r = NewRequest("https://example.org/", "https://example.com", TypeOther)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))
}

func TestContentType(t *testing.T) {
	// $script
	f, err := NewNetworkRule("||example.org^$script", 0)
	r := NewRequest("https://example.org/", "", TypeScript)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = NewRequest("https://example.org/", "", TypeDocument)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	// $script and $stylesheet
	f, err = NewNetworkRule("||example.org^$script,stylesheet", 0)
	r = NewRequest("https://example.org/", "", TypeScript)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = NewRequest("https://example.org/", "", TypeStylesheet)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = NewRequest("https://example.org/", "", TypeDocument)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	// Everything except $script and $stylesheet
	f, err = NewNetworkRule("@@||example.org^$~script,~stylesheet", 0)
	r = NewRequest("https://example.org/", "", TypeScript)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	r = NewRequest("https://example.org/", "", TypeStylesheet)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	r = NewRequest("https://example.org/", "", TypeDocument)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))
}

func TestDomainRestrictions(t *testing.T) {
	// Just one permitted domain
	f, err := NewNetworkRule("||example.org^$domain=example.org", 0)
	r := NewRequest("https://example.org/", "", TypeScript)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	r = NewRequest("https://example.org/", "https://example.org/", TypeScript)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = NewRequest("https://example.org/", "https://subdomain.example.org/", TypeScript)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	// One permitted, subdomain restricted
	f, err = NewNetworkRule("||example.org^$domain=example.org|~subdomain.example.org", 0)
	r = NewRequest("https://example.org/", "", TypeScript)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	r = NewRequest("https://example.org/", "https://example.org/", TypeScript)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = NewRequest("https://example.org/", "https://subdomain.example.org/", TypeScript)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	// One restricted
	f, err = NewNetworkRule("||example.org^$domain=~example.org", 0)
	r = NewRequest("https://example.org/", "", TypeScript)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = NewRequest("https://example.org/", "https://example.org/", TypeScript)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	r = NewRequest("https://example.org/", "https://subdomain.example.org/", TypeScript)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))
}

func TestInvalidDomainRestrictions(t *testing.T) {
	_, err := NewNetworkRule("||example.org^$domain=", 0)
	assert.NotNil(t, err)

	_, err = NewNetworkRule("||example.org^$domain=|example.com", 0)
	assert.NotNil(t, err)
}

func TestNetworkRuleSerialize(t *testing.T) {
	ruleText := "||example.org^$domain=example.org|~subdomain.example.org"
	rule, err := NewNetworkRule(ruleText, -1)
	assert.Nil(t, err)
	assert.NotNil(t, rule)

	b := bytes.Buffer{}
	length, err := SerializeRule(rule, &b)
	assert.Nil(t, err)
	assert.Equal(t, length, b.Len())

	log.Printf("Rule text length: %d", len(ruleText))
	log.Printf("Serialized length: %d", length)

	r, err := DeserializeRule(&b)
	assert.Nil(t, err)
	assert.NotNil(t, r)

	deserializedRule := r.(*NetworkRule)
	assert.True(t, reflect.DeepEqual(rule, deserializedRule))
}
