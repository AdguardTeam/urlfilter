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

	testSubHostname = "sub.test.example"

	testLongTLDHostname = "example.org.uk"

	testOtherHostname = "other.example"
)

// Common URLs for tests.
var (
	testURL = &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   testHostname,
	}

	testSubURL = &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   testSubHostname,
	}

	testLongTLDURL = &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   testLongTLDHostname,
	}

	testOtherURL = &url.URL{
		Scheme: urlutil.SchemeHTTPS,
		Host:   testOtherHostname,
	}
)
