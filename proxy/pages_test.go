package proxy

import (
	"net/url"
	"testing"

	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/urlfilter/internal/uftest"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
)

func TestBuildBlockedPage(t *testing.T) {
	s := &Session{
		Request: rules.NewRequest(&url.URL{
			Scheme: urlutil.SchemeHTTPS,
			Host:   uftest.Host,
		}, nil, rules.TypeDocument),
	}

	r := uftest.NewNetworkRule(t, uftest.RuleHost)

	page := buildBlockedPage(s, r)
	assert.Contains(t, page, uftest.Host)
}
