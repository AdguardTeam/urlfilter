package urlfilter

import (
	"encoding/json"
	"testing"

	"github.com/AdguardTeam/urlfilter/filterlist"
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

	t.Logf("%s", jsonString)
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

	t.Logf("%s", jsonString)
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

	t.Logf("%s", jsonString)
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

	t.Logf("%s", jsonString)
}

func buildCosmeticEngine(t *testing.T) *CosmeticEngine {
	rulesText := `##banner_generic
##banner_generic_disabled
example.org##banner_specific
example.org#@#banner_generic_disabled`

	lists := []filterlist.RuleList{
		&filterlist.StringRuleList{
			ID:             1,
			RulesText:      rulesText,
			IgnoreCosmetic: false,
		},
	}

	ruleStorage, err := filterlist.NewRuleStorage(lists)
	if err != nil {
		t.Fatalf("failed to create a rule storage: %s", err)
	}

	return NewCosmeticEngine(ruleStorage)
}
