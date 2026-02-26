package proxy

import (
	"testing"

	"github.com/AdguardTeam/urlfilter/internal/uftest"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
)

func TestBuildBlockedPage(t *testing.T) {
	t.Parallel()

	s := &Session{
		Request: rules.NewRequest(uftest.URLStrHost, "", rules.TypeDocument),
	}

	r := uftest.NewNetworkRule(t, uftest.RuleHost)

	page := buildBlockedPage(s, r)
	assert.Contains(t, page, uftest.Host)
}
