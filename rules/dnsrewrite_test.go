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

		r, err := NewNetworkRule("||example.org^$dnsrewrite=", -1)
		assert.Nil(t, err)
		assert.True(t, r.Match(req))

		r, err = NewNetworkRule("||example.org^$dnsrewrite", -1)
		assert.Nil(t, err)
		assert.True(t, r.Match(req))

		r, err = NewNetworkRule("||example.org^$dnsrewrite=127.0.0.1", -1)
		assert.Nil(t, err)
		assert.True(t, r.Match(req))

		r, err = NewNetworkRule("||example.org^$dnsrewrite=::1", -1)
		assert.Nil(t, err)
		assert.True(t, r.Match(req))

		r, err = NewNetworkRule("||example.org^$dnsrewrite=example.net", -1)
		assert.Nil(t, err)
		assert.True(t, r.Match(req))

		r, err = NewNetworkRule("||example.org^$dnsrewrite=REFUSED", -1)
		assert.Nil(t, err)
		assert.True(t, r.Match(req))

		r, err = NewNetworkRule("||example.org^$dnsrewrite=noerror;a;127.0.0.1", -1)
		assert.Nil(t, err)
		assert.True(t, r.Match(req))

		r, err = NewNetworkRule("||example.org^$dnsrewrite=noerror;aaaa;::1", -1)
		assert.Nil(t, err)
		assert.True(t, r.Match(req))

		r, err = NewNetworkRule("||example.org^$dnsrewrite=noerror;cname;example.net", -1)
		assert.Nil(t, err)
		assert.True(t, r.Match(req))

		r, err = NewNetworkRule("||example.org^$dnsrewrite=noerror;txt;hello", -1)
		assert.Nil(t, err)
		assert.True(t, r.Match(req))

		r, err = NewNetworkRule("||example.org^$dnsrewrite=noerror;mx;30 example.net", -1)
		assert.Nil(t, err)
		assert.True(t, r.Match(req))

		r, err = NewNetworkRule("||example.org^$dnsrewrite=noerror;svcb;30 example.net alpn=h3", -1)
		assert.Nil(t, err)
		assert.True(t, r.Match(req))

		r, err = NewNetworkRule("||example.org^$dnsrewrite=noerror;https;30 example.net", -1)
		assert.Nil(t, err)
		assert.True(t, r.Match(req))

		r, err = NewNetworkRule("||example.org^$dnsrewrite=nxdomain;;", -1)
		assert.Nil(t, err)
		assert.True(t, r.Match(req))
	})

	t.Run("success_reverse", func(t *testing.T) {
		req := NewRequestForHostname("1.2.3.4.in-addr.arpa")

		r, err := NewNetworkRule("||1.2.3.4.in-addr.arpa^$dnsrewrite=noerror;ptr;example.net", -1)
		assert.Nil(t, err)
		assert.True(t, r.Match(req))
	})

	t.Run("parse_errors", func(t *testing.T) {
		_, err := NewNetworkRule("||example.org^$dnsrewrite=BADKEYWORD", -1)
		assert.NotNil(t, err)

		_, err = NewNetworkRule("||example.org^$dnsrewrite=bad;syntax", -1)
		assert.NotNil(t, err)

		_, err = NewNetworkRule("||example.org^$dnsrewrite=nonexisting;nonexisting;nonexisting", -1)
		assert.NotNil(t, err)

		_, err = NewNetworkRule("||example.org^$dnsrewrite=noerror;nonexisting;nonexisting", -1)
		assert.NotNil(t, err)

		_, err = NewNetworkRule("||example.org^$dnsrewrite=noerror;a;badip", -1)
		assert.NotNil(t, err)

		_, err = NewNetworkRule("||example.org^$dnsrewrite=noerror;aaaa;badip", -1)
		assert.NotNil(t, err)

		_, err = NewNetworkRule("||example.org^$dnsrewrite=noerror;aaaa;127.0.0.1", -1)
		assert.NotNil(t, err)

		_, err = NewNetworkRule("||example.org^$dnsrewrite=noerror;mx;bad stuff", -1)
		assert.NotNil(t, err)

		_, err = NewNetworkRule("||example.org^$dnsrewrite=noerror;mx;very bad stuff", -1)
		assert.NotNil(t, err)

		_, err = NewNetworkRule("||example.org^$dnsrewrite=noerror;https;bad stuff", -1)
		assert.NotNil(t, err)

		_, err = NewNetworkRule("||example.org^$dnsrewrite=noerror;svcb;bad stuff", -1)
		assert.NotNil(t, err)

		_, err = NewNetworkRule("||example.org^$dnsrewrite=noerror;svcb;42 bad stuffs", -1)
		assert.NotNil(t, err)

		// See https://github.com/AdguardTeam/AdGuardHome/issues/2492.
		_, err = NewNetworkRule("||example.org^$dnsrewrite=A:NOERROR:127.0.0.1", -1)
		assert.NotNil(t, err)
	})
}
