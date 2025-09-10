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

// Common URLs for tests.
var (
	testURL = &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   testHostname,
	}

	testURLLongTLD = &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   testHostnameLongTLD,
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
