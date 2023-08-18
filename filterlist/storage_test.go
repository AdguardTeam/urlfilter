package filterlist

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRuleStorage2(t *testing.T) {
	list1 := &StringRuleList{
		ID:             1,
		RulesText:      "||example.org\n! test\n##banner",
		IgnoreCosmetic: false,
	}
	list2 := &StringRuleList{
		ID:             2,
		RulesText:      "||example.com\n! test\n##advert",
		IgnoreCosmetic: false,
	}

	// Create storage from two lists
	storage, err := NewRuleStorage([]RuleList{list1, list2})
	assert.Nil(t, err)

	// Create a scanner instance
	scanner := storage.NewRuleStorageScanner()
	assert.NotNil(t, scanner)

	// Time to scan!

	// Rule 1 from the list 1
	assert.True(t, scanner.Scan())
	f, idx := scanner.Rule()

	assert.NotNil(t, f)
	assert.Equal(t, "||example.org", f.Text())
	assert.Equal(t, 1, f.GetFilterListID())
	assert.Equal(t, "0x0000000100000000", int642hex(idx))

	// Rule 2 from the list 1
	assert.True(t, scanner.Scan())
	f, idx = scanner.Rule()

	assert.NotNil(t, f)
	assert.Equal(t, "##banner", f.Text())
	assert.Equal(t, 1, f.GetFilterListID())
	assert.Equal(t, "0x0000000100000015", int642hex(idx))

	// Rule 1 from the list 2
	assert.True(t, scanner.Scan())
	f, idx = scanner.Rule()

	assert.NotNil(t, f)
	assert.Equal(t, "||example.com", f.Text())
	assert.Equal(t, 2, f.GetFilterListID())
	assert.Equal(t, "0x0000000200000000", int642hex(idx))

	// Rule 2 from the list 2
	assert.True(t, scanner.Scan())
	f, idx = scanner.Rule()

	assert.NotNil(t, f)
	assert.Equal(t, "##advert", f.Text())
	assert.Equal(t, 2, f.GetFilterListID())
	assert.Equal(t, "0x0000000200000015", int642hex(idx))

	// Now check that there's nothing to read
	assert.False(t, scanner.Scan())

	// Check that nothing breaks if we read a finished scanner
	assert.False(t, scanner.Scan())

	// Time to retrieve!

	// Rule 1 from the list 1
	f, err = storage.RetrieveRule(0x0000000100000000)
	assert.Nil(t, err)
	assert.NotNil(t, f)
	assert.Equal(t, "||example.org", f.Text())

	// Rule 2 from the list 1
	f, err = storage.RetrieveRule(0x0000000100000015)
	assert.Nil(t, err)
	assert.NotNil(t, f)
	assert.Equal(t, "##banner", f.Text())

	// Rule 1 from the list 2
	f, err = storage.RetrieveRule(0x0000000200000000)
	assert.Nil(t, err)
	assert.NotNil(t, f)
	assert.Equal(t, "||example.com", f.Text())

	// Rule 2 from the list 2
	f, err = storage.RetrieveRule(0x0000000200000015)
	assert.Nil(t, err)
	assert.NotNil(t, f)
	assert.Equal(t, "##advert", f.Text())
}

func TestRuleStorage2InvalidLists(t *testing.T) {
	_, err := NewRuleStorage([]RuleList{
		&StringRuleList{ID: 1, RulesText: ""},
		&StringRuleList{ID: 1, RulesText: ""},
	})
	assert.NotNil(t, err)
}
