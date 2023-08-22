package rules

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			testutil.AssertErrorMsg(t, tc.want, err)
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
			name: "svcb_dohpath",
			in:   "||example.org^$dnsrewrite=noerror;svcb;30 example.net alpn=h3 dohpath=/dns-query{?dns}",
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
		}, {
			name: "empty",
			in:   "||example.org^$dnsrewrite=noerror;;",
		}}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				r, err := NewNetworkRule(tc.in, -1)
				require.NoError(t, err)

				assert.True(t, r.Match(req))
			})
		}
	})

	t.Run("success_reverse", func(t *testing.T) {
		r, err := NewNetworkRule("||1.2.3.4.in-addr.arpa^$dnsrewrite=noerror;ptr;example.net", -1)
		require.NoError(t, err)

		req := NewRequestForHostname("1.2.3.4.in-addr.arpa")
		assert.True(t, r.Match(req))
	})

	t.Run("parse_errors", func(t *testing.T) {
		testCases := []struct {
			name       string
			in         string
			wantErrMsg string
		}{{
			name:       "short_bad_keyword",
			in:         "||example.org^$dnsrewrite=BADKEYWORD",
			wantErrMsg: `unknown keyword: "BADKEYWORD"`,
		}, {
			name:       "short_bad_syntax",
			in:         "||example.org^$dnsrewrite=bad;syntax",
			wantErrMsg: `invalid dnsrewrite: expected zero or two delimiters`,
		}, {
			name:       "nonexisting",
			in:         "||example.org^$dnsrewrite=nonexisting;nonexisting;nonexisting",
			wantErrMsg: `unknown rcode: "nonexisting"`,
		}, {
			name:       "noerror_nonexisting",
			in:         "||example.org^$dnsrewrite=noerror;nonexisting;nonexisting",
			wantErrMsg: `dns rr type "nonexisting" is invalid`,
		}, {
			name:       "noerror_not_quite_empty",
			in:         "||example.org^$dnsrewrite=noerror;;127.0.0.1",
			wantErrMsg: `dns rr type "" is invalid`,
		}, {
			name:       "a_bad_ip",
			in:         "||example.org^$dnsrewrite=noerror;a;badip",
			wantErrMsg: `"badip" is not a valid ipv4`,
		}, {
			name:       "aaaa_bad_ip",
			in:         "||example.org^$dnsrewrite=noerror;aaaa;badip",
			wantErrMsg: `"badip" is not a valid ipv6`,
		}, {
			name:       "aaaa_ipv4",
			in:         "||example.org^$dnsrewrite=noerror;aaaa;127.0.0.1",
			wantErrMsg: `"127.0.0.1" is an ipv4, not an ipv6`,
		}, {
			name: "cname_bad_host",
			in:   "||example.org^$dnsrewrite=noerror;cname;!!badstuff",
			wantErrMsg: `invalid cname host: invalid hostname part at index 0: ` +
				`invalid char '!' at index 0`,
		}, {
			name: "mx_bad_types",
			in:   "||example.org^$dnsrewrite=noerror;mx;bad stuff",
			wantErrMsg: `invalid mx preference: strconv.ParseUint: ` +
				`parsing "bad": invalid syntax`,
		}, {
			name:       "mx_bad_num",
			in:         "||example.org^$dnsrewrite=noerror;mx;badstuff",
			wantErrMsg: `invalid mx: "badstuff"`,
		}, {
			name: "mx_bad_host",
			in:   "||example.org^$dnsrewrite=noerror;mx;10 !!badstuff",
			wantErrMsg: `invalid mx exchange: invalid hostname part at index 0: ` +
				`invalid char '!' at index 0`,
		}, {
			name: "ptr_bad_host",
			in:   "||example.org^$dnsrewrite=noerror;ptr;bad stuff",
			wantErrMsg: `invalid ptr host: invalid hostname part at index 0: ` +
				`invalid char ' ' at index 3`,
		}, {
			name: "https_bad_prio",
			in:   "||example.org^$dnsrewrite=noerror;https;bad stuff",
			wantErrMsg: `invalid https priority: strconv.ParseUint: ` +
				`parsing "bad": invalid syntax`,
		}, {
			name:       "svcb_bad_num",
			in:         "||example.org^$dnsrewrite=noerror;svcb;badstuff",
			wantErrMsg: `invalid svcb "badstuff": need at least two fields`,
		}, {
			name: "svcb_bad_prio",
			in:   "||example.org^$dnsrewrite=noerror;svcb;bad stuff",
			wantErrMsg: `invalid svcb priority: strconv.ParseUint: ` +
				`parsing "bad": invalid syntax`,
		}, {
			name:       "svcb_bad_params",
			in:         "||example.org^$dnsrewrite=noerror;svcb;42 bad stuffs",
			wantErrMsg: `invalid svcb param at index 0: got 1 fields`,
		}, {
			name: "svcb_bad_host",
			in:   "||example.org^$dnsrewrite=noerror;svcb;42 !!badstuff alpn=h3",
			wantErrMsg: `invalid svcb target: invalid hostname part at index 0: ` +
				`invalid char '!' at index 0`,
		}, {
			// See https://github.com/AdguardTeam/AdGuardHome/issues/2492.
			name: "adguard_home_issue_2492",
			in:   "||example.org^$dnsrewrite=A:NOERROR:127.0.0.1",
			wantErrMsg: `invalid shorthand hostname "A:NOERROR:127.0.0.1": ` +
				`invalid hostname part at index 0: invalid char ':' at index 1`,
		}, {
			name:       "srv_bad_num",
			in:         "||example.org^$dnsrewrite=noerror;srv;bad stuff",
			wantErrMsg: `invalid srv "bad stuff": need four fields`,
		}, {
			name: "srv_bad_prio",
			in:   "||example.org^$dnsrewrite=noerror;srv;bad 0 0 stuff",
			wantErrMsg: `invalid srv priority: strconv.ParseUint: ` +
				`parsing "bad": invalid syntax`,
		}, {
			name: "srv_bad_weight",
			in:   "||example.org^$dnsrewrite=noerror;srv;30 bad 0 stuff",
			wantErrMsg: `invalid srv weight: strconv.ParseUint: ` +
				`parsing "bad": invalid syntax`,
		}, {
			name: "srv_bad_port",
			in:   "||example.org^$dnsrewrite=noerror;srv;30 60 bad stuff",
			wantErrMsg: `invalid srv port: strconv.ParseUint: ` +
				`parsing "bad": invalid syntax`,
		}, {
			name: "srv_bad_host",
			in:   "||example.org^$dnsrewrite=noerror;srv;30 60 8080 !!badstuff",
			wantErrMsg: `invalid srv target: invalid hostname part at index 0: ` +
				`invalid char '!' at index 0`,
		}}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := NewNetworkRule(tc.in, -1)
				testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			})
		}

		for _, tc := range []struct {
			rcode      string
			wantErrMsg string
		}{{
			rcode:      "NOERROR",
			wantErrMsg: ``,
		}, {
			rcode:      "FORMERR",
			wantErrMsg: `unknown keyword: "FORMERR"`,
		}, {
			rcode:      "SERVFAIL",
			wantErrMsg: ``,
		}, {
			rcode:      "NXDOMAIN",
			wantErrMsg: ``,
		}, {
			rcode:      "NOTIMP",
			wantErrMsg: `unknown keyword: "NOTIMP"`,
		}, {
			rcode:      "REFUSED",
			wantErrMsg: ``,
		}, {
			rcode:      "YXDOMAIN",
			wantErrMsg: `unknown keyword: "YXDOMAIN"`,
		}, {
			rcode:      "YXRRSET",
			wantErrMsg: `unknown keyword: "YXRRSET"`,
		}, {
			rcode:      "NXRRSET",
			wantErrMsg: `unknown keyword: "NXRRSET"`,
		}, {
			rcode:      "NOTAUTH",
			wantErrMsg: `unknown keyword: "NOTAUTH"`,
		}, {
			rcode:      "NOTZONE",
			wantErrMsg: `unknown keyword: "NOTZONE"`,
		}, {
			rcode:      "BADSIG",
			wantErrMsg: `unknown keyword: "BADSIG"`,
		}, {
			rcode:      "BADKEY",
			wantErrMsg: `unknown keyword: "BADKEY"`,
		}, {
			rcode:      "BADTIME",
			wantErrMsg: `unknown keyword: "BADTIME"`,
		}, {
			rcode:      "BADMODE",
			wantErrMsg: `unknown keyword: "BADMODE"`,
		}, {
			rcode:      "BADNAME",
			wantErrMsg: `unknown keyword: "BADNAME"`,
		}, {
			rcode:      "BADALG",
			wantErrMsg: `unknown keyword: "BADALG"`,
		}, {
			rcode:      "BADTRUNC",
			wantErrMsg: `unknown keyword: "BADTRUNC"`,
		}, {
			rcode:      "BADCOOKIE",
			wantErrMsg: `unknown keyword: "BADCOOKIE"`,
		}} {
			t.Run("short_keyword_"+strings.ToLower(tc.rcode), func(t *testing.T) {
				rule := fmt.Sprintf("||example.org^$dnsrewrite=%s", tc.rcode)
				_, err := NewNetworkRule(rule, -1)
				testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			})
		}
	})
}
