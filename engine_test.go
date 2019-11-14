package urlfilter

import (
	"testing"

	"github.com/AdguardTeam/urlfilter/filterlist"

	"github.com/AdguardTeam/urlfilter/rules"

	"github.com/stretchr/testify/assert"
)

func TestEngineMatchRequest(t *testing.T) {
	rulesText := `||example.org^$third-party`
	engine := buildEngine(t, rulesText)

	request := rules.NewRequest("https://example.org", "", rules.TypeDocument)
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

	return NewEngine(ruleStorage)
}
