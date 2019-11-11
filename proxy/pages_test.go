package proxy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AdguardTeam/urlfilter"
)

func TestBuildBlockedPage(t *testing.T) {
	s := &Session{
		Request: urlfilter.NewRequest("https://example.org/", "", urlfilter.TypeDocument),
	}
	f, err := urlfilter.NewNetworkRule("||example.org^", 0)
	assert.Nil(t, err)

	page := buildBlockedPage(s, f)
	assert.True(t, strings.Index(page, "example.org") > 0)
}
