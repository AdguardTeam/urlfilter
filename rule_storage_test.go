package urlfilter

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRuleStorage(t *testing.T) {
	hostRules := []string{
		"127.0.1.1       thishost.mydomain.org  thishost",
		"209.237.226.90  www.opensource.org",
		"::1             localhost ip6-localhost ip6-loopback",
	}
	filterListID := 1

	s, err := NewRuleStorage("")
	assert.Nil(t, err)

	for _, ruleText := range hostRules {
		rule, err := NewHostRule(ruleText, filterListID)
		assert.Nil(t, err)

		idx, err := s.Store(rule)
		assert.Nil(t, err)

		retrieved, err := s.Retrieve(idx)
		assert.Nil(t, err)

		assert.True(t, reflect.DeepEqual(rule, retrieved))
	}
}
