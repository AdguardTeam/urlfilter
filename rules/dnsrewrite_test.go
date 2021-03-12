package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateHost(t *testing.T) {
	testCases := []struct {
		name string
		in   string
		want string
	}{{
		name: "success",
		in:   "example.com",
		want: "",
	}, {
		name: "success_punycode",
		// Aka "имена.бг".
		in:   "xn--80ajiqg.xn--90ae",
		want: "",
	}, {
		name: "empty",
		in:   "",
		want: "invalid hostname length: 0",
	}, {
		name: "too_long",
		in:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		want: "invalid hostname length: 64",
	}, {
		name: "empty_part",
		in:   "example..com",
		want: "empty hostname part at index 1",
	}, {
		name: "bad_part_first",
		in:   "www.-example.com",
		want: "invalid hostname part at index 1: invalid char '-' at index 0",
	}, {
		name: "bad_part_inner",
		in:   "www:example.com",
		want: "invalid hostname part at index 0: invalid char ':' at index 3",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHost(tc.in)
			if err != nil {
				assert.Equal(t, tc.want, err.Error())

				return
			}

			if tc.want != "" {
				t.Errorf("want error %q, got nil", tc.want)
			}
		})
	}
}

func TestNetworkRule_Match_dnsRewrite(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		req := NewRequestForHostname("example.org")

		testCases := []struct {
			name string
			in   string
		}{{
			name: "empty",
			in:   "||example.org^$dnsrewrite=",
		}, {
			name: "empty_no_equals",
			in:   "||example.org^$dnsrewrite",
		}, {
			name: "short_a",
			in:   "||example.org^$dnsrewrite=127.0.0.1",
		}, {
			name: "short_aaaa",
			in:   "||example.org^$dnsrewrite=::1",
		}, {
			name: "short_cname",
			in:   "||example.org^$dnsrewrite=example.net",
		}, {
			name: "short_keyword",
			in:   "||example.org^$dnsrewrite=REFUSED",
		}, {
			name: "a",
			in:   "||example.org^$dnsrewrite=noerror;a;127.0.0.1",
		}, {
			name: "aaaa",
			in:   "||example.org^$dnsrewrite=noerror;aaaa;::1",
		}, {
			name: "cname",
			in:   "||example.org^$dnsrewrite=noerror;cname;example.net",
		}, {
			name: "txt",
			in:   "||example.org^$dnsrewrite=noerror;txt;hello",
		}, {
			name: "mx",
			in:   "||example.org^$dnsrewrite=noerror;mx;30 example.net",
		}, {
			name: "svcb",
			in:   "||example.org^$dnsrewrite=noerror;svcb;30 example.net alpn=h3",
		}, {
			name: "svcb_dot",
			in:   "||example.org^$dnsrewrite=noerror;svcb;30 . alpn=h3",
		}, {
			name: "https",
			in:   "||example.org^$dnsrewrite=noerror;https;30 example.net",
		}, {
			name: "nxdomain",
			in:   "||example.org^$dnsrewrite=nxdomain;;",
		}, {
			name: "srv",
			in:   "||example.org^$dnsrewrite=noerror;srv;30 60 8080 example.net",
		}, {
			name: "srv_dot",
			in:   "||example.org^$dnsrewrite=noerror;srv;30 60 8080 .",
		}}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				r, err := NewNetworkRule(tc.in, -1)
				assert.Nil(t, err)
				assert.True(t, r.Match(req))
			})
		}
	})

	t.Run("success_reverse", func(t *testing.T) {
		req := NewRequestForHostname("1.2.3.4.in-addr.arpa")

		r, err := NewNetworkRule("||1.2.3.4.in-addr.arpa^$dnsrewrite=noerror;ptr;example.net", -1)
		assert.Nil(t, err)
		assert.True(t, r.Match(req))
	})

	t.Run("parse_errors", func(t *testing.T) {
		testCases := []struct {
			name string
			in   string
		}{{
			name: "short_bad_keyword",
			in:   "||example.org^$dnsrewrite=BADKEYWORD",
		}, {
			name: "short_bad_syntax",
			in:   "||example.org^$dnsrewrite=bad;syntax",
		}, {
			name: "nonexisting",
			in:   "||example.org^$dnsrewrite=nonexisting;nonexisting;nonexisting",
		}, {
			name: "noerror_nonexisting",
			in:   "||example.org^$dnsrewrite=noerror;nonexisting;nonexisting",
		}, {
			name: "a_bad_ip",
			in:   "||example.org^$dnsrewrite=noerror;a;badip",
		}, {
			name: "aaaa_bad_ip",
			in:   "||example.org^$dnsrewrite=noerror;aaaa;badip",
		}, {
			name: "aaaa_ipv4",
			in:   "||example.org^$dnsrewrite=noerror;aaaa;127.0.0.1",
		}, {
			name: "cname_bad_host",
			in:   "||example.org^$dnsrewrite=noerror;cname;!!badstuff",
		}, {
			name: "mx_bad_types",
			in:   "||example.org^$dnsrewrite=noerror;mx;bad stuff",
		}, {
			name: "mx_bad_num",
			in:   "||example.org^$dnsrewrite=noerror;mx;badstuff",
		}, {
			name: "mx_bad_host",
			in:   "||example.org^$dnsrewrite=noerror;mx;10 !!badstuff",
		}, {
			name: "ptr_bad_host",
			in:   "||example.org^$dnsrewrite=noerror;ptr;bad stuff",
		}, {
			name: "https_bad_prio",
			in:   "||example.org^$dnsrewrite=noerror;https;bad stuff",
		}, {
			name: "svcb_bad_num",
			in:   "||example.org^$dnsrewrite=noerror;svcb;badstuff",
		}, {
			name: "svcb_bad_prio",
			in:   "||example.org^$dnsrewrite=noerror;svcb;bad stuff",
		}, {
			name: "svcb_bad_params",
			in:   "||example.org^$dnsrewrite=noerror;svcb;42 bad stuffs",
		}, {
			name: "svcb_bad_host",
			in:   "||example.org^$dnsrewrite=noerror;svcb;42 !!badstuff alpn=h3",
		}, {
			// See https://github.com/AdguardTeam/AdGuardHome/issues/2492.
			name: "adguard_home_issue_2492",
			in:   "||example.org^$dnsrewrite=A:NOERROR:127.0.0.1",
		}, {
			name: "srv_bad_num",
			in:   "||example.org^$dnsrewrite=noerror;srv;bad stuff",
		}, {
			name: "srv_bad_prio",
			in:   "||example.org^$dnsrewrite=noerror;srv;bad 0 0 stuff",
		}, {
			name: "srv_bad_weight",
			in:   "||example.org^$dnsrewrite=noerror;srv;30 bad 0 stuff",
		}, {
			name: "srv_bad_port",
			in:   "||example.org^$dnsrewrite=noerror;srv;30 60 bad stuff",
		}, {
			name: "srv_bad_host",
			in:   "||example.org^$dnsrewrite=noerror;srv;30 60 8080 !!badstuff",
		}}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := NewNetworkRule(tc.in, -1)
				assert.NotNil(t, err)
			})
		}
	})
}
