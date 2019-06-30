package urlfilter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStringRuleListScanner(t *testing.T) {
	ruleList := &StringRuleList{
		ID:             1,
		IgnoreCosmetic: false,
		RulesText:      "||example.org\n! test\n##banner",
	}
	assert.Equal(t, 1, ruleList.GetID())

	scanner := ruleList.NewScanner()

	assert.True(t, scanner.Scan())
	f, idx := scanner.Rule()

	assert.NotNil(t, f)
	assert.Equal(t, "||example.org", f.Text())
	assert.Equal(t, 1, f.GetFilterListID())
	assert.Equal(t, 0, idx)

	assert.True(t, scanner.Scan())
	f, idx = scanner.Rule()

	assert.NotNil(t, f)
	assert.Equal(t, "##banner", f.Text())
	assert.Equal(t, 1, f.GetFilterListID())
	assert.Equal(t, 21, idx)

	// Finish scanning
	assert.False(t, scanner.Scan())

	f, err := ruleList.RetrieveRule(0)
	assert.Nil(t, err)
	assert.NotNil(t, f)
	assert.Equal(t, "||example.org", f.Text())
	assert.Equal(t, 1, f.GetFilterListID())

	f, err = ruleList.RetrieveRule(21)
	assert.NotNil(t, f)
	assert.Equal(t, "##banner", f.Text())
	assert.Equal(t, 1, f.GetFilterListID())
}
