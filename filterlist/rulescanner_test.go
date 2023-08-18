package filterlist

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const hostsPath = testResourcesDir + "/hosts"

func TestRuleScannerOfStringReader(t *testing.T) {
	filterList := "||example.org\n! test\n##banner"
	r := strings.NewReader(filterList)
	scanner := NewRuleScanner(r, 1, false)

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

	assert.False(t, scanner.Scan())
	assert.False(t, scanner.Scan())
}

func TestRuleScannerOfFileReader(t *testing.T) {
	file, err := os.Open(hostsPath)
	if err != nil {
		t.Fatalf("cannot open hosts file: %s", err)
	}

	// 55997 valid rules in the hosts file
	scanner := NewRuleScanner(file, 1, true)
	rulesCount := 0
	for scanner.Scan() {
		f, idx := scanner.Rule()
		assert.NotNil(t, f)
		assert.True(t, idx > 0)
		rulesCount++
	}

	assert.Equal(t, 55997, rulesCount)
	assert.False(t, scanner.Scan())
}
