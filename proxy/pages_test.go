package proxy

import (
	"strings"
	"testing"

	"github.com/AdguardTeam/urlfilter/rules"

	"github.com/stretchr/testify/assert"
)

func TestBuildBlockedPage(t *testing.T) {
	s := &Session{
		Request: rules.NewRequest("https://example.org/", "", rules.TypeDocument),
	}
	f, err := rules.NewNetworkRule("||example.org^", 0)
	assert.Nil(t, err)

	page := buildBlockedPage(s, f)
	assert.True(t, strings.Index(page, "example.org") > 0)
}
