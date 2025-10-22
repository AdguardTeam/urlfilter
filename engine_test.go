package urlfilter_test

import (
	"testing"

	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/internal/uftest"

	"github.com/AdguardTeam/urlfilter/rules"

	"github.com/stretchr/testify/assert"
)

func TestEngine_MatchRequest(t *testing.T) {
	t.Parallel()

	rulesText := `||example.org^$third-party`
	engine := newTestEngine(t, rulesText)

	request := rules.NewRequest("https://example.org", "", rules.TypeDocument)
	result := engine.MatchRequest(request)

	assert.Nil(t, result.BasicRule)
	assert.Nil(t, result.DocumentRule)
	assert.Nil(t, result.ReplaceRules)
	assert.Nil(t, result.CspRules)
	assert.Nil(t, result.CookieRules)
	assert.Nil(t, result.StealthRule)
}

func FuzzNewEngine(f *testing.F) {
	for _, seed := range []string{
		"",
		" ",
		"\n",
		"1",
		"!",
		"#",
		"# comment",
		"##banner",
		"127.0.0.1",
		"example.test",
		"::1 localhost",
		"209.237.226.90 example.test",
		"fe80::1 # comment",
		"||example.org^",
		"/regex/",
		"@@||example.org^$third-party",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, rulesText string) {
		assert.NotPanics(t, func() {
			_ = newTestEngine(t, rulesText)
		})
	})
}

// newTestEngine builds filtering engine from the specified set of rules and
// adds its rule storage close method to tb's cleanup.
func newTestEngine(tb testing.TB, rulesText string) (engine *urlfilter.Engine) {
	tb.Helper()

	return urlfilter.NewEngine(newTestRuleStorage(tb, uftest.ListID1, rulesText))
}
