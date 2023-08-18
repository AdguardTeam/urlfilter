package filterlist

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRuleStorageScanner(t *testing.T) {
	// Create two filter lists

	filterList1 := "||example.org\n! test\n##banner"
	r1 := strings.NewReader(filterList1)
	scanner1 := NewRuleScanner(r1, 1, false)

	filterList2 := "||example.com\n! test\n##advert"
	r2 := strings.NewReader(filterList2)
	scanner2 := NewRuleScanner(r2, 2, false)

	// Now create the storage scanner
	storageScanner := &RuleStorageScanner{
		Scanners: []*RuleScanner{scanner1, scanner2},
	}

	// Time to scan

	// Rule 1 from the list 1
	assert.True(t, storageScanner.Scan())
	f, idx := storageScanner.Rule()

	assert.NotNil(t, f)
	assert.Equal(t, "||example.org", f.Text())
	assert.Equal(t, 1, f.GetFilterListID())
	assert.Equal(t, "0x0000000100000000", int642hex(idx))

	// Rule 2 from the list 1
	assert.True(t, storageScanner.Scan())
	f, idx = storageScanner.Rule()

	assert.NotNil(t, f)
	assert.Equal(t, "##banner", f.Text())
	assert.Equal(t, 1, f.GetFilterListID())
	assert.Equal(t, "0x0000000100000015", int642hex(idx))

	// Rule 1 from the list 2
	assert.True(t, storageScanner.Scan())
	f, idx = storageScanner.Rule()

	assert.NotNil(t, f)
	assert.Equal(t, "||example.com", f.Text())
	assert.Equal(t, 2, f.GetFilterListID())
	assert.Equal(t, "0x0000000200000000", int642hex(idx))

	// Rule 2 from the list 2
	assert.True(t, storageScanner.Scan())
	f, idx = storageScanner.Rule()

	assert.NotNil(t, f)
	assert.Equal(t, "##advert", f.Text())
	assert.Equal(t, 2, f.GetFilterListID())
	assert.Equal(t, "0x0000000200000015", int642hex(idx))

	// Now check that there's nothing to read
	assert.False(t, storageScanner.Scan())

	// Check that nothing breaks if we read a finished scanner
	assert.False(t, storageScanner.Scan())
}

func int642hex(v int64) string {
	return fmt.Sprintf("0x%016x", v)
}
