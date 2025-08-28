package proxy

import (
	"net/url"
	"strings"
	"testing"

	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/urlfilter/rules"

	"github.com/stretchr/testify/assert"
)

func TestBuildBlockedPage(t *testing.T) {
	s := &Session{
		Request: rules.NewRequest(&url.URL{
			Scheme: urlutil.SchemeHTTPS,
			Host:   "test.example",
		}, nil, rules.TypeDocument),
	}
	f, err := rules.NewNetworkRule("||test.example^", 0)
	assert.Nil(t, err)

	page := buildBlockedPage(s, f)
	assert.True(t, strings.Index(page, "test.example") > 0)
}
