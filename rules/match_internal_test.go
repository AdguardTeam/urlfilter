package rules

import (
	"testing"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilterNegatedRules(t *testing.T) {
	t.Parallel()

	ruleA := newNetworkRule(t, "||a.example^")
	ruleB := newNetworkRule(t, "||b.example^")
	badfilterA := newNetworkRule(t, "||a.example^$badfilter")
	badfilterB := newNetworkRule(t, "||b.example^$badfilter")
	badfilterC := newNetworkRule(t, "||c.example^$badfilter")

	testCases := []struct {
		name           string
		want           []*NetworkRule
		badfilterRules []*NetworkRule
		rules          []*NetworkRule
	}{
		{
			name:           "matching_and_unrelated",
			want:           nil,
			badfilterRules: []*NetworkRule{badfilterA, badfilterB},
			rules:          []*NetworkRule{ruleA, badfilterA, badfilterB},
		},
		{
			name:           "several_unrelated",
			want:           []*NetworkRule{ruleA},
			badfilterRules: []*NetworkRule{badfilterB, badfilterC},
			rules:          []*NetworkRule{ruleA, badfilterB, badfilterC},
		},
		{
			name:           "existing_behavior",
			want:           []*NetworkRule{ruleB},
			badfilterRules: []*NetworkRule{badfilterA},
			rules:          []*NetworkRule{ruleA, ruleB, badfilterA},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, filterNegatedRules(tc.badfilterRules, tc.rules))
		})
	}
}

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
