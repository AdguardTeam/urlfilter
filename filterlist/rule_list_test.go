package filterlist

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

const testResourcesDir = "../testdata"

func TestStringRuleListScanner(t *testing.T) {
	ruleList := &StringRuleList{
		ID:             1,
		IgnoreCosmetic: false,
		RulesText:      "||example.org\n! test\n##banner",
	}
	defer ruleList.Close()
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
	assert.Nil(t, err)
	assert.NotNil(t, f)
	assert.Equal(t, "##banner", f.Text())
	assert.Equal(t, 1, f.GetFilterListID())
}

func TestFileRuleListScanner(t *testing.T) {
	ruleList, err := NewFileRuleList(1, filepath.Join(testResourcesDir, "test_file_rule_list.txt"), false)
	if err != nil {
		t.Fatalf("couldn't create rule list: %s", err)
	}
	defer ruleList.Close()
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

	f, err = ruleList.RetrieveRule(0)
	assert.Nil(t, err)
	assert.NotNil(t, f)
	assert.Equal(t, "||example.org", f.Text())
	assert.Equal(t, 1, f.GetFilterListID())

	f, err = ruleList.RetrieveRule(21)
	assert.Nil(t, err)
	assert.NotNil(t, f)
	assert.Equal(t, "##banner", f.Text())
	assert.Equal(t, 1, f.GetFilterListID())
}
