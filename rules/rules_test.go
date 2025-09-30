package rules_test

import (
	"net/url"

	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/urlfilter/rules"
)

// Common ListIDs for tests.
const (
	testListID rules.ListID = 1
)

// Common hostnames for tests.
const (
	testHostname = "test.example"

	testHostnameSub = "sub.test.example"

	testHostnameLongTLD = "example.org.uk"

	testHostnameOther = "other.example"
)

// Common rule for tests.
const testRule = "||" + testHostname + "^"

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
