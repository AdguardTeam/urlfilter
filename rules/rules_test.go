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

// Common hostnames and URL strings for tests.
const (
	testURLStrDoubleTLD = urlutil.SchemeHTTP + "://" + testHostnameLongTLD
)

// Common URLs for tests.
var (
	testURL = &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   uftest.Host,
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
