package rules

import (
	"fmt"
	"strings"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/urlfilter/internal/geoip"
	"github.com/AdguardTeam/urlfilter/internal/ufnet"
	"github.com/miekg/dns"
)

// Rule is a base interface for all filtering rules.
//
// TODO(a.garipov):  Rename to Interface.
type Rule interface {
	// Text returns the original rule text.
	//
	// TODO(a.garipov):  Replace with String.
	Text() (s string)

	// GetFilterListID returns ID of the filter list this rule belongs to.
	//
	// TODO(a.garipov):  Rename to ListID.
	GetFilterListID() (id ListID)
}

// NewRule creates a new filtering rule from the specified line.  It returns nil
// if the line is empty or if it is a comment.
func NewRule(line string, id ListID) (r Rule, err error) {
	if line = strings.TrimSpace(line); line == "" || isComment(line) {
		return nil, nil
	}

	if isCosmetic(line) {
		return NewCosmeticRule(line, id)
	}

	// TODO(a.garipov):  Optimize.
	hr, err := NewHostRule(line, id)
	if err == nil {
		return hr, nil
	}

	return NewNetworkRule(line, id)
}

// isComment returns true if the line is a comment.
func isComment(line string) (ok bool) {
	if len(line) == 0 {
		return false
	}

	if line[0] == '!' {
		return true
	}

	if line[0] == '#' {
		if len(line) == 1 {
			return true
		}

		// Now we should check that this is not a cosmetic rule.
		for _, marker := range cosmeticRulesMarkers {
			if strings.HasPrefix(line, marker) {
				return false
			}
		}

		return true
	}

	return false
}

// parseDomains parses the $domain modifier or cosmetic rules domains.  sep is
// the separator character.  For network rules it is '|'; for cosmetic, ','.
func parseDomains(domains, sep string) (permittedDomains, restrictedDomains []string, err error) {
	if domains == "" {
		// TODO(a.garipov):  Here and in the whole package, use the standard
		// error values.
		return nil, nil, errors.Error("no domains specified")
	}

	list := strings.Split(domains, sep)
	for i := range list {
		d := list[i]
		restricted := false
		if strings.HasPrefix(d, restrictionMarker) {
			restricted = true
			d = d[1:]
		}

		if !ufnet.IsDomainName(d) && !strings.HasSuffix(d, ".*") {
			err = fmt.Errorf("invalid domain specified: %s", domains)

			return permittedDomains, restrictedDomains, err
		}

		if restricted {
			restrictedDomains = append(restrictedDomains, d)
		} else {
			permittedDomains = append(permittedDomains, d)
		}
	}

	return permittedDomains, restrictedDomains, nil
}

// strToRRType converts s to a DNS resource record (RR) type.  s may be in any
// letter case.
func strToRRType(s string) (rr RRType, err error) {
	// TypeNone and TypeReserved are special cases in package dns.
	if strings.EqualFold(s, "none") || strings.EqualFold(s, "reserved") {
		return 0, errors.Error("dns rr type is none or reserved")
	}

	rr, ok := dns.StringToType[strings.ToUpper(s)]
	if !ok {
		return 0, fmt.Errorf("dns rr type %q is invalid", s)
	}

	return rr, nil
}

// parseDNSTypes parses the $dnstype modifier.  types is the list of types.
func parseDNSTypes(types string) (permittedTypes, restrictedTypes []RRType, err error) {
	if types == "" {
		return nil, nil, fmt.Errorf("parsing dns types: %w", errors.ErrEmptyValue)
	}

	list := strings.Split(types, "|")
	for i, rrStr := range list {
		var rr RRType
		var isRestricted bool
		rr, isRestricted, err = parseDNSType(rrStr)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing dns type: at index %d: %w", i, err)
		}

		if isRestricted {
			restrictedTypes = append(restrictedTypes, rr)

			continue
		}

		permittedTypes = append(permittedTypes, rr)
	}

	return permittedTypes, restrictedTypes, nil
}

// parseDNSType parses DNS resource record type.  If rrStr has a restricted rule
// prefix, isRestricted will be true.
func parseDNSType(rrStr string) (rrType RRType, isRestricted bool, err error) {
	if len(rrStr) == 0 {
		return 0, false, errors.ErrEmptyValue
	}

	isRestricted = rrStr[0:1] == restrictionMarker
	if isRestricted {
		rrStr = rrStr[1:]
	}

	var rr RRType
	rr, err = strToRRType(rrStr)
	if err != nil {
		return 0, false, fmt.Errorf("converting string to RRType: %w", err)
	}

	return rr, isRestricted, nil
}

// isValidCTag returns true if ctag value format is correct.
func isValidCTag(s string) (ok bool) {
	for _, ch := range s {
		if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '_' {
			return false
		}
	}

	return true
}

// geoIPData contains GeoIP restriction and permission lists.
type geoIPData struct {
	permittedASNs       []geoip.ASN
	restrictedASNs      []geoip.ASN
	permittedCountries  []string
	restrictedCountries []string
}

// parseGeoIP parses the GeoIP data from the $respgeo modifier.  rule must not
// be nil.
func parseGeoIP(rule *NetworkRule, value, sep string) (err error) {
	data := geoIPData{}

	idx := 0
	for value := range strings.SplitSeq(value, sep) {
		err = parseGeoIPValue(&data, value)
		if err != nil {
			return fmt.Errorf("parsing geoip value at index %d: %w", idx, err)
		}

		idx++
	}

	rule.permittedASNs = container.NewSortedSliceSet(data.permittedASNs...)
	rule.permittedCountries = container.NewSortedSliceSet(data.permittedCountries...)
	rule.restrictedASNs = container.NewSortedSliceSet(data.restrictedASNs...)
	rule.restrictedCountries = container.NewSortedSliceSet(data.restrictedCountries...)

	return nil
}

// parseGeoIPValue parses a single ASN or Country value from $respgeo modifier.
// data must not be nil.
func parseGeoIPValue(data *geoIPData, value string) (err error) {
	if value == "" {
		return errors.ErrEmptyValue
	}

	isRestricted := false
	if strings.HasPrefix(value, restrictionMarker) {
		isRestricted = true
		value = value[1:]
	}

	if value == emptyCountry || value == emptyASN {
		isEmptyASN := value == emptyASN
		appendGeoIPValue(data, isEmptyASN, isRestricted, geoip.CountryNone, geoip.ASNNone)

		return nil
	}

	isASN := false
	var asnVal geoip.ASN
	if strings.HasPrefix(value, geoip.ASNPrefix) {
		asnVal, err = geoip.NewASN(value)
		if err != nil {
			return fmt.Errorf("parsing asn: %w", err)
		}

		isASN = true
	}

	appendGeoIPValue(data, isASN, isRestricted, value, asnVal)

	return nil
}

// appendGeoIPValue appends an ASN or country value to data.  The country value
// will be lowercased first.  data must not be nil.
func appendGeoIPValue(
	data *geoIPData,
	isASN bool,
	isRestricted bool,
	country geoip.Country,
	asn geoip.ASN,
) {
	if isASN {
		if isRestricted {
			data.restrictedASNs = append(data.restrictedASNs, asn)
		} else {
			data.permittedASNs = append(data.permittedASNs, asn)
		}
	} else {
		country = strings.ToLower(country)
		if isRestricted {
			data.restrictedCountries = append(data.restrictedCountries, country)
		} else {
			data.permittedCountries = append(data.permittedCountries, country)
		}
	}
}

// parseCTags parses tags from the $ctag modifier.  sep is the separator
// character; for network rules it is '|'.
func parseCTags(value, sep string) (permittedSet, restrictedSet *container.SortedSliceSet[string], err error) {
	if value == "" {
		return nil, nil, errors.ErrEmptyValue
	}

	var restricted, permitted []string
	list := strings.Split(value, sep)
	for i := range list {
		d := list[i]
		isRestricted := false
		if strings.HasPrefix(d, restrictionMarker) {
			isRestricted = true
			d = d[1:]
		}

		if !isValidCTag(d) {
			err = fmt.Errorf("invalid ctag specified: %q", value)

			break
		}

		if isRestricted {
			restricted = append(restricted, d)
		} else {
			permitted = append(permitted, d)
		}
	}

	permittedSet = container.NewSortedSliceSet(permitted...)
	restrictedSet = container.NewSortedSliceSet(restricted...)

	return permittedSet, restrictedSet, err
}

// parseClients parses the client modifier string with the specified separator
// byte.
//
// The $client modifier allows specifying clients this rule will be working for.
// It accepts client names, IP addresses, or CIDR address ranges.
//
// The syntax is:
//
//	$client=value1|value2|...
//
// It is also possible to restrict clients by adding a '~' before the client IP
// or name.  In this case, the rule will not be applied to this client's
// requests:
//
//	$client=~value1
//
// # Specifying client names
//
// Client names can contain spaces or other special characters.  These should be
// enclosed in quotes; both double-quotes and single-quotes are supported.  If
// the client name contains quotes, use '\' to escape them.  Commas ',' and
// pipes '|' should also be escaped.
//
// Please note, that when specifying a restricted client, you must keep `~` out
// of the quotes.
//
// Examples of the input values:
//
//	127.0.0.1
//	192.168.3.0/24
//	::
//	fe01::/64
//	'Frank\'s laptop'
//	"Frank's phone"
//	~'Mary\'s\, John\'s\, and Boris\'s laptops'
//	~Mom|~Dad|"Kids"
//
// TODO(d.kolyshev):  Use permitted and restricted as structs, not pointers.
func parseClients(value string, sep byte) (permitted, restricted *clients, err error) {
	if value == "" {
		return nil, nil, errors.ErrEmptyValue
	}

	for _, client := range splitWithEscapeCharacter(value, sep, '\\') {
		permitted, restricted, err = appendClient(client, permitted, restricted)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid $client value: %w", err)
		}
	}

	return permitted, restricted, nil
}

// appendClient adds a client to the specified set.  Creates the set if needed.
func appendClient(
	client string,
	permittedOrig *clients,
	restrictedOrig *clients,
) (permitted, restricted *clients, err error) {
	permitted = permittedOrig
	restricted = restrictedOrig

	client, isRestricted, err := parseClient(client)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return permitted, restricted, err
	}

	if isRestricted {
		if restricted == nil {
			restricted = newClients()
		}
		restricted.add(client)
	} else {
		if permitted == nil {
			permitted = newClients()
		}
		permitted.add(client)
	}

	return permitted, restricted, nil
}

// parseClient parses a single client string.
func parseClient(input string) (client string, isRestricted bool, err error) {
	client = input

	// 1. Check if this is a restricted or permitted client.
	if strings.HasPrefix(client, restrictionMarker) {
		isRestricted = true
		client = client[1:]
	}

	// 2. Check if quoted.
	quoteChar := isQuoted(client)

	// 3. If quoted, remove quotes.
	if quoteChar > 0 {
		client = client[1 : len(client)-1]
	}

	// 4. Unescape commas and quotes.
	client = strings.ReplaceAll(client, "\\,", ",")
	if quoteChar > 0 {
		quoteStr := string(quoteChar)
		client = strings.ReplaceAll(client, "\\"+quoteStr, quoteStr)
	}

	if client == "" {
		return "", false, fmt.Errorf("invalid value %q", input)
	}

	return client, isRestricted, nil
}

// isQuoted returns the quote character if the input is quoted, or 0 otherwise.
func isQuoted(input string) (quoteChar uint8) {
	if len(input) >= 2 &&
		(input[0] == '\'' || input[0] == '"') &&
		input[0] == input[len(input)-1] {
		quoteChar = input[0]
	}

	return quoteChar
}
