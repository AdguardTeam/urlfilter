package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoveDNSRewriteRules(t *testing.T) {
	rs := []*NetworkRule{{
		RuleText:   "host1",
		DNSRewrite: nil,
	}, {
		RuleText:   "host2",
		DNSRewrite: nil,
	}, {
		RuleText:   "host3",
		DNSRewrite: nil,
	}}

	got := removeDNSRewriteRules(rs)
	assert.Equal(t, rs, got)

	rs = []*NetworkRule{{
		RuleText:   "host1",
		DNSRewrite: nil,
	}, {
		RuleText:   "host2",
		DNSRewrite: &DNSRewrite{},
	}, {
		RuleText:   "host3",
		DNSRewrite: nil,
	}}

	got = removeDNSRewriteRules(rs)
	require.Len(t, got, 2)

	assert.Equal(t, "host1", got[0].RuleText)
	assert.Equal(t, "host3", got[1].RuleText)
}
