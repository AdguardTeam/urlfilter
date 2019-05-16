package urlfilter

import (
	"encoding/json"
	"log"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestElementHidingSimple(t *testing.T) {
	engine := buildCosmeticEngine(t)

	// Simple matching
	result := engine.Match("example.org", true, true, true)
	assert.NotNil(t, result)

	assert.Contains(t, result.ElementHiding.Generic, "banner_generic")
	assert.Equal(t, 1, len(result.ElementHiding.Generic))
	assert.NotContains(t, result.ElementHiding.Generic, "banner_generic_disabled")
	assert.Equal(t, 1, len(result.ElementHiding.Specific))
	assert.Contains(t, result.ElementHiding.Specific, "banner_specific")
	assert.Nil(t, result.ElementHiding.GenericExtCSS)
	assert.Nil(t, result.ElementHiding.SpecificExtCSS)

	jsonString, err := json.MarshalIndent(result, "", "\t")
	if err != nil {
		t.Fatalf("cannot marshal: %s", err)
	}
	log.Print(string(jsonString))
}

func TestElementHidingNoDisabled(t *testing.T) {
	engine := buildCosmeticEngine(t)

	// Simple matching
	result := engine.Match("example.com", true, true, true)
	assert.NotNil(t, result)

	assert.Equal(t, 2, len(result.ElementHiding.Generic))
	assert.Contains(t, result.ElementHiding.Generic, "banner_generic")
	assert.Contains(t, result.ElementHiding.Generic, "banner_generic_disabled")
	assert.Nil(t, result.ElementHiding.Specific)
	assert.Nil(t, result.ElementHiding.GenericExtCSS)
	assert.Nil(t, result.ElementHiding.SpecificExtCSS)

	jsonString, err := json.MarshalIndent(result, "", "\t")
	if err != nil {
		t.Fatalf("cannot marshal: %s", err)
	}
	log.Print(string(jsonString))
}

func TestElementHidingNoGeneric(t *testing.T) {
	engine := buildCosmeticEngine(t)

	// Simple matching
	result := engine.Match("example.org", true, true, false)
	assert.NotNil(t, result)

	assert.Nil(t, result.ElementHiding.Generic)
	assert.Equal(t, 1, len(result.ElementHiding.Specific))
	assert.Contains(t, result.ElementHiding.Specific, "banner_specific")
	assert.Nil(t, result.ElementHiding.GenericExtCSS)
	assert.Nil(t, result.ElementHiding.SpecificExtCSS)

	jsonString, err := json.MarshalIndent(result, "", "\t")
	if err != nil {
		t.Fatalf("cannot marshal: %s", err)
	}
	log.Print(string(jsonString))
}

func TestElementHidingNoCSS(t *testing.T) {
	engine := buildCosmeticEngine(t)

	// Simple matching
	result := engine.Match("example.org", false, true, true)
	assert.NotNil(t, result)

	assert.Nil(t, result.ElementHiding.Specific)
	assert.Nil(t, result.ElementHiding.Generic)
	assert.Nil(t, result.ElementHiding.GenericExtCSS)
	assert.Nil(t, result.ElementHiding.SpecificExtCSS)

	jsonString, err := json.MarshalIndent(result, "", "\t")
	if err != nil {
		t.Fatalf("cannot marshal: %s", err)
	}
	log.Print(string(jsonString))
}

func buildCosmeticEngine(t *testing.T) *CosmeticEngine {
	rulesText := `##banner_generic
##banner_generic_disabled
example.org##banner_specific
example.org#@#banner_generic_disabled`

	var rules []*CosmeticRule
	lines := strings.Split(rulesText, "\n")
	for _, line := range lines {
		if line != "" {
			rule, err := NewCosmeticRule(line, 1)
			if err == nil {
				rules = append(rules, rule)
			} else {
				t.Fatalf("cannot create a rule %s: %s", line, err)
			}
		}
	}
	return NewCosmeticEngine(rules)
}
