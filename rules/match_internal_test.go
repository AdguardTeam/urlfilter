package rules

import (
	"testing"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoveDNSRewriteRules(t *testing.T) {
	t.Parallel()

	rs := []*NetworkRule{
		newNetworkRule(t, "host1"),
		newNetworkRule(t, "host2"),
		newNetworkRule(t, "host3"),
	}

	got := removeDNSRewriteRules(rs)
	assert.Equal(t, rs, got)

	rs = []*NetworkRule{
		errors.Must(NewNetworkRule("host1", testListID)),
		errors.Must(NewNetworkRule("host2^$dnsrewrite=127.0.0.1", testListID)),
		errors.Must(NewNetworkRule("host3", testListID)),
	}

	got = removeDNSRewriteRules(rs)
	require.Len(t, got, 2)

	assert.Equal(t, "host1", got[0].String())
	assert.Equal(t, "host3", got[1].String())
}
