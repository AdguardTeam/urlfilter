package urlfilter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEngineMatchRequest(t *testing.T) {
	rulesText := `||example.org^$third-party`
	engine := buildEngine(t, rulesText)

	request := NewRequest("https://example.org", "", TypeDocument)
	result := engine.MatchRequest(request)

	assert.Nil(t, result.BasicRule)
	assert.Nil(t, result.DocumentRule)
	assert.Nil(t, result.ReplaceRules)
	assert.Nil(t, result.CspRules)
	assert.Nil(t, result.CookieRules)
	assert.Nil(t, result.StealthRule)
}

// buildEngine builds filtering engine from the specified set of rules
func buildEngine(t *testing.T, rulesText string) *Engine {
	lists := []RuleList{
		&StringRuleList{
			ID:             1,
			RulesText:      rulesText,
			IgnoreCosmetic: false,
		},
	}

	ruleStorage, err := NewRuleStorage(lists)
	if err != nil {
		t.Fatalf("failed to create a rule storage: %s", err)
	}

	return NewEngine(ruleStorage)
}
