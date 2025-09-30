package proxy

import (
	"net/url"
	"testing"

	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

// Common domains for tests.
const testDomain = "test.example"

func TestBuildBlockedPage(t *testing.T) {
	t.Parallel()

	s := &Session{
		Request: rules.NewRequest(&url.URL{
			Scheme: urlutil.SchemeHTTPS,
			Host:   testDomain,
		}, nil, rules.TypeDocument),
	}

	r, err := rules.NewNetworkRule("||"+testDomain+"^", 1)
	require.NoError(t, err)

	page := buildBlockedPage(s, r)
	assert.Contains(t, page, testDomain)
}
