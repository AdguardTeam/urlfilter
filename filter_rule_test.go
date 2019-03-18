package urlfilter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseRuleText(t *testing.T) {
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

func TestSimpleBasicRules(t *testing.T) {
	// Simple matching rule
	f, err := NewFilterRule("||example.org^")
	r := NewRequest("https://example.org/", "", TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	// Simple regex rule
	f, err = NewFilterRule("/example\\.org/")
	r = NewRequest("https://example.org/", "", TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))
}

func TestUnknownModifier(t *testing.T) {
	_, err := NewFilterRule("||example.org^$unknown")
	assert.NotNil(t, err)
}

func TestMatchCase(t *testing.T) {
	f, err := NewFilterRule("||example.org^$match-case")
	r := NewRequest("https://example.org/", "", TypeOther)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = NewRequest("https://EXAMPLE.org/", "", TypeOther)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))
}

func TestThirdParty(t *testing.T) {
	f, err := NewFilterRule("||example.org^$third-party")

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

	f, err = NewFilterRule("||example.org^$first-party")

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
	f, err := NewFilterRule("||example.org^$script")
	r := NewRequest("https://example.org/", "", TypeScript)
	assert.Nil(t, err)
	assert.True(t, f.Match(r))

	r = NewRequest("https://example.org/", "", TypeDocument)
	assert.Nil(t, err)
	assert.False(t, f.Match(r))

	// $script and $stylesheet
	f, err = NewFilterRule("||example.org^$script,stylesheet")
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
	f, err = NewFilterRule("@@||example.org^$~script,~stylesheet")
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
