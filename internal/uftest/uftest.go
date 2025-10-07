// Package uftest contains common test data and utilities.
//
// TODO(a.garipov):  Add more constants and use them consistently.
package uftest

import (
	"testing"

	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/require"
)

// Common hostnames for tests.
const (
	Host      = "host.example"
	HostOther = "other.example"
	HostSub   = "sub." + Host
)

// Common rules for tests.
const (
	RuleHost      = rules.MaskStartURL + Host + rules.MaskSeparator
	RuleHostOther = rules.MaskStartURL + HostOther + rules.MaskSeparator
)

// Common URL strings for tests.
const (
	URLStrHost      = urlutil.SchemeHTTP + "://" + Host
	URLStrHostOther = urlutil.SchemeHTTP + "://" + HostOther
	URLStrHostSub   = urlutil.SchemeHTTP + "://" + HostSub
)

// Common list IDs for tests.
const (
	ListID1 rules.ListID = 1
	ListID2 rules.ListID = 2
)

// NewNetworkRule is a helper that wraps [rules.NewNetworkRule].  It uses
// [ListID1] as the list ID.
func NewNetworkRule(tb testing.TB, text string) (r *rules.NetworkRule) {
	tb.Helper()

	r, err := rules.NewNetworkRule(text, ListID1)
	require.NoError(tb, err)

	return r
}
