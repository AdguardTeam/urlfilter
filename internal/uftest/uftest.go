// Package uftest contains common test data and utilities.
//
// TODO(a.garipov):  Add more constants and use them consistently.
package uftest

import (
	"testing"

	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/urlfilter/internal/geoip"
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

// Common GeoIP data for tests.
const (
	ASN1Str     = geoip.ASNPrefix + "12345"
	ASN2Str     = geoip.ASNPrefix + "54321"
	ASNEmptyStr = geoip.ASNPrefix + CountryEmpty

	ASN1 geoip.ASN = 12345
	ASN2 geoip.ASN = 54321

	CountryRU    geoip.Country = "RU"
	CountryFR    geoip.Country = "FR"
	CountryDE    geoip.Country = "DE"
	CountryAS    geoip.Country = "AS"
	CountryEmpty geoip.Country = "--"
)

// NewNetworkRule is a helper that wraps [rules.NewNetworkRule].  It uses
// [ListID1] as the list ID.
func NewNetworkRule(tb testing.TB, text string) (r *rules.NetworkRule) {
	tb.Helper()

	r, err := rules.NewNetworkRule(text, ListID1)
	require.NoError(tb, err)

	return r
}
