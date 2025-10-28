package rules_test

import (
	"net/url"

	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/urlfilter/internal/uftest"
)

// Common hostnames for tests.
const (
	testHostnameLongTLD = "example.org.uk"
)

// Common URLs for tests.
var (
	testURL = &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   uftest.Host,
	}

	testURLDoubleTLD = &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   testHostnameLongTLD,
	}

	testURLSub = &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   uftest.HostSub,
	}

	testURLOther = &url.URL{
		Scheme: urlutil.SchemeHTTPS,
		Host:   uftest.HostOther,
	}
)
