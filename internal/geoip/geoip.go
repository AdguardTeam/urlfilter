// Package geoip contains utilities for working with locations.
package geoip

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/AdguardTeam/golibs/errors"
)

// ASNPrefix is a common prefix of ASN string representation.
const ASNPrefix = "AS"

// ASN is a convenient alias for ASN values.
type ASN = uint32

// ASNNone is a common ASN value for requests that do not have GeoIP data.
const ASNNone ASN = 0

// Country is a convenient alias for country alpha-2 ISO codes.
type Country = string

// CountryNone is a common Country value for requests that do not have GeoIP
// data.
const CountryNone Country = ""

// NewASN converts string into an ASN and makes sure that it is valid.  This
// should be preferred to a simple parsing.
func NewASN(s string) (asn ASN, err error) {
	v, ok := strings.CutPrefix(s, ASNPrefix)
	if !ok {
		return 0, fmt.Errorf("%w: %q does not have a prefix", errors.ErrUnexpectedValue, s)
	}

	asn64, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return 0, err
	}

	return uint32(asn64), nil
}

// IsASNString returns true if s is a valid ASN string.
func IsASNString(s string) (ok bool) {
	return strings.HasPrefix(s, ASNPrefix) && len(s) > len(ASNPrefix)
}
