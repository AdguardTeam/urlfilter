package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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

		r, err = NewNetworkRule("||example.org^$dnsrewrite=noerror;mx;hello", -1)
		assert.Nil(t, err)
		assert.True(t, r.Match(req))

		r, err = NewNetworkRule("||example.org^$dnsrewrite=nxdomain;;", -1)
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
	})
}
