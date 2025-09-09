package rules_test

import (
	"net/url"

	"github.com/AdguardTeam/golibs/netutil/urlutil"
)

// Common list ID for tests.
//
// TODO(a.garipov):  Introduce a type, rules.ListID.
const testListID int = 1

// Common hostnames for tests.
const (
	testHostname = "test.example"

	testHostnameSub = "sub.test.example"

	testHostnameLongTLD = "example.org.uk"

	testHostnameOther = "other.example"
)

// Common hostnames and URL strings for tests.
const (
	schemeHTTP = urlutil.SchemeHTTP + "://"

	testURLStr = schemeHTTP + testHostname

	testURLSubStr = schemeHTTP + testHostnameSub

	testURLLongTLDStr = schemeHTTP + testHostnameLongTLD

	testURLOtherStr = schemeHTTP + testHostnameOther
)

// Common URLs for tests.
var (
	testURL = &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   testHostname,
	}

	testURLSub = &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   testHostnameSub,
	}

	testURLOther = &url.URL{
		Scheme: urlutil.SchemeHTTPS,
		Host:   testHostnameOther,
	}
)
