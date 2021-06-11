package urlfilter

import (
	"net"
	"path"
	"testing"

	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDNSResult_DNSRewrites(t *testing.T) {
	const rulesText = `
|disable-one^$dnsrewrite=127.0.0.1
|disable-one^$dnsrewrite=127.0.0.2
@@||disable-one^$dnsrewrite=127.0.0.1

|priority^$dnsrewrite=127.0.0.1
||priority^

|priority-important^$dnsrewrite=127.0.0.1
||priority-important^$important

|simple-exc^$dnsrewrite=127.0.0.1
@@||simple-exc^

@@|exc-exc^$dnsrewrite=127.0.0.1
@@||exc-exc^

@@||exc-exc-order^
@@|exc-exc-order^$dnsrewrite=127.0.0.1

|disable-cname^$dnsrewrite=127.0.0.1
|disable-cname^$dnsrewrite=new-cname
@@||disable-cname^$dnsrewrite=new-cname

|disable-cname-many^$dnsrewrite=127.0.0.1
|disable-cname-many^$dnsrewrite=new-cname-1
|disable-cname-many^$dnsrewrite=new-cname-2
@@||disable-cname-many^$dnsrewrite=new-cname-1

|disable-all^$dnsrewrite=127.0.0.1
|disable-all^$dnsrewrite=127.0.0.2
@@||disable-all^$dnsrewrite

|disable-all-order^$dnsrewrite=127.0.0.1
@@||disable-all-order^$dnsrewrite=
|disable-all-order^$dnsrewrite=127.0.0.2
`

	ruleStorage := newTestRuleStorage(t, 1, rulesText)
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	ipv4p1 := net.IPv4(127, 0, 0, 1)
	ipv4p2 := net.IPv4(127, 0, 0, 2)

	t.Run("disable-one", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewrites()
		require.Len(t, dnsr, 1)

		dr := dnsr[0].DNSRewrite
		assert.Equal(t, dns.RcodeSuccess, dr.RCode)
		assert.Equal(t, dns.TypeA, dr.RRType)
		assert.Equal(t, ipv4p2, dr.Value)
	})

	t.Run("priority", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))

		// Simple matching.
		assert.True(t, ok)
		assert.Len(t, res.HostRulesV4, 0)

		// DNS rewrite matching.
		dnsr := res.DNSRewrites()
		require.Len(t, dnsr, 1)

		dr := dnsr[0].DNSRewrite
		assert.Equal(t, dns.RcodeSuccess, dr.RCode)
		assert.Equal(t, dns.TypeA, dr.RRType)
		assert.Equal(t, ipv4p1, dr.Value)
	})

	t.Run("priority-important", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))

		// Simple matching.
		assert.True(t, ok)
		require.NotNil(t, res.NetworkRule)

		assert.Contains(t, res.NetworkRule.RuleText, "$important")

		// DNS rewrite matching.
		dnsr := res.DNSRewrites()
		require.Len(t, dnsr, 1)

		dr := dnsr[0].DNSRewrite
		assert.Equal(t, dns.RcodeSuccess, dr.RCode)
		assert.Equal(t, dns.TypeA, dr.RRType)
		assert.Equal(t, ipv4p1, dr.Value)
	})

	t.Run("simple-exc", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))

		// Simple matching.
		assert.True(t, ok)
		assert.True(t, res.NetworkRule.Whitelist)

		// DNS rewrite matching.
		dnsr := res.DNSRewrites()
		require.Len(t, dnsr, 1)

		dr := dnsr[0].DNSRewrite
		assert.Equal(t, dns.RcodeSuccess, dr.RCode)
		assert.Equal(t, dns.TypeA, dr.RRType)
		assert.Equal(t, ipv4p1, dr.Value)
	})

	t.Run("exc-exc", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.True(t, ok)
		assert.True(t, res.NetworkRule.Whitelist)

		// DNS rewrite matching.
		dnsr := res.DNSRewrites()
		require.Len(t, dnsr, 0)
	})

	t.Run("exc-exc-order", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.True(t, ok)
		assert.True(t, res.NetworkRule.Whitelist)

		// DNS rewrite matching.
		dnsr := res.DNSRewrites()
		require.Len(t, dnsr, 0)
	})

	t.Run("disable-cname", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewrites()
		require.Len(t, dnsr, 1)

		dr := dnsr[0].DNSRewrite
		assert.Equal(t, "", dr.NewCNAME)
		assert.Equal(t, dns.RcodeSuccess, dr.RCode)
		assert.Equal(t, dns.TypeA, dr.RRType)
		assert.Equal(t, ipv4p1, dr.Value)
	})

	t.Run("disable-cname-many", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewrites()
		require.Len(t, dnsr, 2)

		dr := dnsr[0].DNSRewrite
		assert.Equal(t, "", dr.NewCNAME)
		assert.Equal(t, dns.RcodeSuccess, dr.RCode)
		assert.Equal(t, dns.TypeA, dr.RRType)
		assert.Equal(t, ipv4p1, dr.Value)

		dr = dnsr[1].DNSRewrite
		assert.Equal(t, "new-cname-2", dr.NewCNAME)
	})

	t.Run("disable-all", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewrites()
		assert.Len(t, dnsr, 0)
	})

	t.Run("disable-all-order", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewrites()
		assert.Len(t, dnsr, 0)
	})
}

func TestDNSEngine_MatchRequest_dnsRewrite(t *testing.T) {
	const rulesText = `
|short-v4^$dnsrewrite=127.0.0.1
|short-v4-multiple^$dnsrewrite=127.0.0.1
|short-v4-multiple^$dnsrewrite=127.0.0.2
|normal-v4^$dnsrewrite=NOERROR;A;127.0.0.1
|normal-v4-multiple^$dnsrewrite=NOERROR;A;127.0.0.1
|normal-v4-multiple^$dnsrewrite=NOERROR;A;127.0.0.2

|short-v6^$dnsrewrite=::1
|short-v6-multiple^$dnsrewrite=::1
|short-v6-multiple^$dnsrewrite=::2
|normal-v6^$dnsrewrite=NOERROR;AAAA;::1
|normal-v6-multiple^$dnsrewrite=NOERROR;AAAA;::1
|normal-v6-multiple^$dnsrewrite=NOERROR;AAAA;::2

|refused-host^$dnsrewrite=REFUSED
|new-cname^$dnsrewrite=othercname
|new-mx^$dnsrewrite=NOERROR;MX;32 new-mx-host
|new-txt^$dnsrewrite=NOERROR;TXT;new-txtcontent
|1.2.3.4.in-addr.arpa^$dnsrewrite=NOERROR;PTR;new-ptr
|1.2.3.5.in-addr.arpa^$dnsrewrite=NOERROR;PTR;new-ptr-with-dot.

|https-record^$dnsrewrite=NOERROR;HTTPS;32 https-record-host alpn=h3
|svcb-record^$dnsrewrite=NOERROR;SVCB;32 svcb-record-host alpn=h3

|https-type^$dnstype=HTTPS,dnsrewrite=REFUSED

|disable-one^$dnsrewrite=127.0.0.1
|disable-one^$dnsrewrite=127.0.0.2
@@||disable-one^$dnsrewrite=127.0.0.1

|disable-all^$dnsrewrite=127.0.0.1
|disable-all^$dnsrewrite=127.0.0.2
@@||disable-all^$dnsrewrite

|disable-all-alt-syntax^$dnsrewrite=127.0.0.1
|disable-all-alt-syntax^$dnsrewrite=127.0.0.2
@@||disable-all-alt-syntax^$dnsrewrite=

@@||blocked-later^$dnsrewrite
||blocked-later^

@@||etc-hosts-rule^$dnsrewrite
127.0.0.1 etc-hosts-rule

||bad-shorthand^$dnsrewrite=A:NOERROR:127.0.0.1

|srv-record^$dnsrewrite=NOERROR;SRV;30 60 8080 srv-record-host
`

	ruleStorage := newTestRuleStorage(t, 1, rulesText)
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	ipv4p1 := net.IPv4(127, 0, 0, 1)
	ipv4p2 := net.IPv4(127, 0, 0, 2)
	ipv6p1 := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	ipv6p2 := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

	t.Run("short-v4", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 1)

		nr := dnsr[0]
		assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
		assert.Equal(t, dns.TypeA, nr.DNSRewrite.RRType)
		assert.Equal(t, ipv4p1, nr.DNSRewrite.Value)
	})

	t.Run("short-v4-multiple", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 2)

		nr := dnsr[0]
		assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
		assert.Equal(t, dns.TypeA, nr.DNSRewrite.RRType)
		assert.Equal(t, ipv4p1, nr.DNSRewrite.Value)

		nr = dnsr[1]
		assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
		assert.Equal(t, dns.TypeA, nr.DNSRewrite.RRType)
		assert.Equal(t, ipv4p2, nr.DNSRewrite.Value)
	})

	t.Run("normal-v4", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 1)

		nr := dnsr[0]
		assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
		assert.Equal(t, dns.TypeA, nr.DNSRewrite.RRType)
		assert.Equal(t, ipv4p1, nr.DNSRewrite.Value)
	})

	t.Run("normal-v4-multiple", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 2)

		nr := dnsr[0]
		assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
		assert.Equal(t, dns.TypeA, nr.DNSRewrite.RRType)
		assert.Equal(t, ipv4p1, nr.DNSRewrite.Value)

		nr = dnsr[1]
		assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
		assert.Equal(t, dns.TypeA, nr.DNSRewrite.RRType)
		assert.Equal(t, ipv4p2, nr.DNSRewrite.Value)
	})

	t.Run("short-v6", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 1)

		nr := dnsr[0]
		assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
		assert.Equal(t, dns.TypeAAAA, nr.DNSRewrite.RRType)
		assert.Equal(t, ipv6p1, nr.DNSRewrite.Value)
	})

	t.Run("short-v6-multiple", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 2)

		nr := dnsr[0]
		assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
		assert.Equal(t, dns.TypeAAAA, nr.DNSRewrite.RRType)
		assert.Equal(t, ipv6p1, nr.DNSRewrite.Value)

		nr = dnsr[1]
		assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
		assert.Equal(t, dns.TypeAAAA, nr.DNSRewrite.RRType)
		assert.Equal(t, ipv6p2, nr.DNSRewrite.Value)
	})

	t.Run("normal-v6", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 1)

		nr := dnsr[0]
		assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
		assert.Equal(t, dns.TypeAAAA, nr.DNSRewrite.RRType)
		assert.Equal(t, ipv6p1, nr.DNSRewrite.Value)
	})

	t.Run("normal-v6-multiple", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 2)

		nr := dnsr[0]
		assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
		assert.Equal(t, dns.TypeAAAA, nr.DNSRewrite.RRType)
		assert.Equal(t, ipv6p1, nr.DNSRewrite.Value)

		nr = dnsr[1]
		assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
		assert.Equal(t, dns.TypeAAAA, nr.DNSRewrite.RRType)
		assert.Equal(t, ipv6p2, nr.DNSRewrite.Value)
	})

	t.Run("refused-host", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 1)

		nr := dnsr[0]
		assert.Equal(t, dns.RcodeRefused, nr.DNSRewrite.RCode)
	})

	t.Run("new-cname", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 1)

		nr := dnsr[0]
		assert.Equal(t, "othercname", nr.DNSRewrite.NewCNAME)
	})

	t.Run("new-mx", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 1)

		nr := dnsr[0]
		assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
		assert.Equal(t, dns.TypeMX, nr.DNSRewrite.RRType)

		mx := &rules.DNSMX{
			Exchange:   "new-mx-host",
			Preference: 32,
		}
		assert.Equal(t, mx, nr.DNSRewrite.Value)
	})

	t.Run("new-txt", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 1)

		nr := dnsr[0]
		assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
		assert.Equal(t, dns.TypeTXT, nr.DNSRewrite.RRType)
		assert.Equal(t, "new-txtcontent", nr.DNSRewrite.Value)
	})

	t.Run("1.2.3.4.in-addr.arpa", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 1)

		nr := dnsr[0]
		assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
		assert.Equal(t, dns.TypePTR, nr.DNSRewrite.RRType)
		assert.Equal(t, "new-ptr.", nr.DNSRewrite.Value)
	})

	t.Run("1.2.3.5.in-addr.arpa", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 1)

		nr := dnsr[0]
		assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
		assert.Equal(t, dns.TypePTR, nr.DNSRewrite.RRType)
		assert.Equal(t, "new-ptr-with-dot.", nr.DNSRewrite.Value)
	})

	t.Run("https-record", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 1)

		nr := dnsr[0]
		assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
		assert.Equal(t, dns.TypeHTTPS, nr.DNSRewrite.RRType)

		p := map[string]string{
			"alpn": "h3",
		}
		svcb := &rules.DNSSVCB{
			Params:   p,
			Target:   "https-record-host",
			Priority: 32,
		}
		assert.Equal(t, svcb, nr.DNSRewrite.Value)
	})

	t.Run("svcb-record", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 1)

		nr := dnsr[0]
		assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
		assert.Equal(t, dns.TypeSVCB, nr.DNSRewrite.RRType)

		p := map[string]string{
			"alpn": "h3",
		}
		svcb := &rules.DNSSVCB{
			Params:   p,
			Target:   "svcb-record-host",
			Priority: 32,
		}
		assert.Equal(t, svcb, nr.DNSRewrite.Value)
	})

	t.Run("https-type", func(t *testing.T) {
		r := DNSRequest{
			Hostname: path.Base(t.Name()),
			DNSType:  dns.TypeHTTPS,
		}

		res, ok := dnsEngine.MatchRequest(r)
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 1)

		nr := dnsr[0]
		assert.Equal(t, dns.RcodeRefused, nr.DNSRewrite.RCode)

		r = DNSRequest{
			Hostname: "https-type",
			DNSType:  dns.TypeA,
		}

		_, ok = dnsEngine.MatchRequest(r)
		assert.False(t, ok)
	})

	t.Run("disable-one", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 3)

		var allowListCase *rules.NetworkRule
		for _, r := range dnsr {
			if r.Whitelist {
				allowListCase = r
			}
		}

		require.NotNil(t, allowListCase)

		dr := allowListCase.DNSRewrite
		assert.Equal(t, dns.RcodeSuccess, dr.RCode)
		assert.Equal(t, dns.TypeA, dr.RRType)
		assert.Equal(t, ipv4p1, dr.Value)
	})

	t.Run("disable-all", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 3)

		var allowListCase *rules.NetworkRule
		for _, r := range dnsr {
			if r.Whitelist {
				allowListCase = r
			}
		}

		require.NotNil(t, allowListCase)
		assert.Equal(t, &rules.DNSRewrite{}, allowListCase.DNSRewrite)
	})

	t.Run("disable-all-alt-syntax", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 3)

		var allowListCase *rules.NetworkRule
		for _, r := range dnsr {
			if r.Whitelist {
				allowListCase = r
			}
		}

		require.NotNil(t, allowListCase)
		assert.Equal(t, &rules.DNSRewrite{}, allowListCase.DNSRewrite)
	})

	t.Run("blocked-later", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		require.True(t, ok)
		require.NotNil(t, res.NetworkRule)

		assert.Equal(t, "||blocked-later^", res.NetworkRule.RuleText)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 1)

		assert.True(t, dnsr[0].Whitelist)
	})

	t.Run("etc-hosts-rule", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		require.True(t, ok)
		require.Len(t, res.HostRulesV4, 1)

		assert.Equal(t, "127.0.0.1 etc-hosts-rule", res.HostRulesV4[0].RuleText)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 1)

		assert.True(t, dnsr[0].Whitelist)
	})

	// See https://github.com/AdguardTeam/AdGuardHome/issues/2492.
	t.Run("bad-shorthand", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		assert.Nil(t, dnsr)
	})

	t.Run("srv-record", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		require.Len(t, dnsr, 1)

		nr := dnsr[0]
		assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
		assert.Equal(t, dns.TypeSRV, nr.DNSRewrite.RRType)

		srv := &rules.DNSSRV{
			Target:   "srv-record-host",
			Priority: 30,
			Weight:   60,
			Port:     8080,
		}
		assert.Equal(t, srv, nr.DNSRewrite.Value)
	})
}
