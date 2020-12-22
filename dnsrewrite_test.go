package urlfilter

import (
	"net"
	"path"
	"testing"

	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestDNSResult_DNSRewrites(t *testing.T) {
	const rulesText = `
|disable_one^$dnsrewrite=127.0.0.1
|disable_one^$dnsrewrite=127.0.0.2
@@||disable_one^$dnsrewrite=127.0.0.1

|simple_exc^$dnsrewrite=127.0.0.1
@@||simple_exc^

|disable_cname^$dnsrewrite=127.0.0.1
|disable_cname^$dnsrewrite=new_cname
@@||disable_cname^$dnsrewrite=new_cname

|disable_cname_many^$dnsrewrite=127.0.0.1
|disable_cname_many^$dnsrewrite=new_cname_1
|disable_cname_many^$dnsrewrite=new_cname_2
@@||disable_cname_many^$dnsrewrite=new_cname_1

|disable_all^$dnsrewrite=127.0.0.1
|disable_all^$dnsrewrite=127.0.0.2
@@||disable_all^$dnsrewrite

|disable_all_order^$dnsrewrite=127.0.0.1
@@||disable_all_order^$dnsrewrite=
|disable_all_order^$dnsrewrite=127.0.0.2
`

	ruleStorage := newTestRuleStorage(t, 1, rulesText)
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	ipv4p1 := net.IPv4(127, 0, 0, 1)
	ipv4p2 := net.IPv4(127, 0, 0, 2)

	t.Run("disable_one", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewrites()
		if assert.Len(t, dnsr, 1) {
			dr := dnsr[0].DNSRewrite
			assert.Equal(t, dns.RcodeSuccess, dr.RCode)
			assert.Equal(t, dns.TypeA, dr.RRType)
			assert.Equal(t, ipv4p2, dr.Value)
		}
	})

	t.Run("simple_exc", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))

		// Simple matching.
		assert.True(t, ok)
		assert.True(t, res.NetworkRule.Whitelist)

		// DNS rewrite matching.
		dnsr := res.DNSRewrites()
		if assert.Len(t, dnsr, 1) {
			dr := dnsr[0].DNSRewrite
			assert.Equal(t, dns.RcodeSuccess, dr.RCode)
			assert.Equal(t, dns.TypeA, dr.RRType)
			assert.Equal(t, ipv4p1, dr.Value)
		}
	})

	t.Run("disable_cname", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewrites()
		if assert.Len(t, dnsr, 1) {
			dr := dnsr[0].DNSRewrite
			assert.Equal(t, "", dr.NewCNAME)
			assert.Equal(t, dns.RcodeSuccess, dr.RCode)
			assert.Equal(t, dns.TypeA, dr.RRType)
			assert.Equal(t, ipv4p1, dr.Value)
		}
	})

	t.Run("disable_cname_many", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewrites()
		if assert.Len(t, dnsr, 2) {
			dr := dnsr[0].DNSRewrite
			assert.Equal(t, "", dr.NewCNAME)
			assert.Equal(t, dns.RcodeSuccess, dr.RCode)
			assert.Equal(t, dns.TypeA, dr.RRType)
			assert.Equal(t, ipv4p1, dr.Value)

			dr = dnsr[1].DNSRewrite
			assert.Equal(t, "new_cname_2", dr.NewCNAME)
		}
	})

	t.Run("disable_all", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewrites()
		assert.Len(t, dnsr, 0)
	})

	t.Run("disable_all_order", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewrites()
		assert.Len(t, dnsr, 0)
	})
}

func TestDNSEngine_MatchRequest_dnsRewrite(t *testing.T) {
	const rulesText = `
|short_v4^$dnsrewrite=127.0.0.1
|short_v4_multiple^$dnsrewrite=127.0.0.1
|short_v4_multiple^$dnsrewrite=127.0.0.2
|normal_v4^$dnsrewrite=NOERROR;A;127.0.0.1
|normal_v4_multiple^$dnsrewrite=NOERROR;A;127.0.0.1
|normal_v4_multiple^$dnsrewrite=NOERROR;A;127.0.0.2

|short_v6^$dnsrewrite=::1
|short_v6_multiple^$dnsrewrite=::1
|short_v6_multiple^$dnsrewrite=::2
|normal_v6^$dnsrewrite=NOERROR;AAAA;::1
|normal_v6_multiple^$dnsrewrite=NOERROR;AAAA;::1
|normal_v6_multiple^$dnsrewrite=NOERROR;AAAA;::2

|refused_host^$dnsrewrite=REFUSED
|new_cname^$dnsrewrite=othercname
|new_mx^$dnsrewrite=NOERROR;MX;32 new_mx_host
|new_txt^$dnsrewrite=NOERROR;TXT;new_txtcontent
|1.2.3.4.in-addr.arpa^$dnsrewrite=NOERROR;PTR;new_ptr

|https_record^$dnsrewrite=NOERROR;HTTPS;32 https_record_host alpn=h3
|svcb_record^$dnsrewrite=NOERROR;SVCB;32 svcb_record_host alpn=h3

|https_type^$dnstype=HTTPS,dnsrewrite=REFUSED

|disable_one^$dnsrewrite=127.0.0.1
|disable_one^$dnsrewrite=127.0.0.2
@@||disable_one^$dnsrewrite=127.0.0.1

|disable_all^$dnsrewrite=127.0.0.1
|disable_all^$dnsrewrite=127.0.0.2
@@||disable_all^$dnsrewrite

|disable_all_alt_syntax^$dnsrewrite=127.0.0.1
|disable_all_alt_syntax^$dnsrewrite=127.0.0.2
@@||disable_all_alt_syntax^$dnsrewrite=

@@||blocked_later^$dnsrewrite
||blocked_later^

@@||etc_hosts_rule^$dnsrewrite
127.0.0.1 etc_hosts_rule
`

	ruleStorage := newTestRuleStorage(t, 1, rulesText)
	dnsEngine := NewDNSEngine(ruleStorage)
	assert.NotNil(t, dnsEngine)

	ipv4p1 := net.IPv4(127, 0, 0, 1)
	ipv4p2 := net.IPv4(127, 0, 0, 2)
	ipv6p1 := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	ipv6p2 := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

	t.Run("short_v4", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		if assert.Len(t, dnsr, 1) {
			nr := dnsr[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv4p1, nr.DNSRewrite.Value)
		}
	})

	t.Run("short_v4_multiple", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		if assert.Len(t, dnsr, 2) {
			nr := dnsr[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv4p1, nr.DNSRewrite.Value)

			nr = dnsr[1]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv4p2, nr.DNSRewrite.Value)
		}
	})

	t.Run("normal_v4", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		if assert.Len(t, dnsr, 1) {
			nr := dnsr[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv4p1, nr.DNSRewrite.Value)
		}
	})

	t.Run("normal_v4_multiple", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		if assert.Len(t, dnsr, 2) {
			nr := dnsr[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv4p1, nr.DNSRewrite.Value)

			nr = dnsr[1]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv4p2, nr.DNSRewrite.Value)
		}
	})

	t.Run("short_v6", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		if assert.Len(t, dnsr, 1) {
			nr := dnsr[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeAAAA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv6p1, nr.DNSRewrite.Value)
		}
	})

	t.Run("short_v6_multiple", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		if assert.Len(t, dnsr, 2) {
			nr := dnsr[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeAAAA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv6p1, nr.DNSRewrite.Value)

			nr = dnsr[1]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeAAAA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv6p2, nr.DNSRewrite.Value)
		}
	})

	t.Run("normal_v6", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		if assert.Len(t, dnsr, 1) {
			nr := dnsr[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeAAAA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv6p1, nr.DNSRewrite.Value)
		}
	})

	t.Run("normal_v6_multiple", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		if assert.Len(t, dnsr, 2) {
			nr := dnsr[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeAAAA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv6p1, nr.DNSRewrite.Value)

			nr = dnsr[1]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeAAAA, nr.DNSRewrite.RRType)
			assert.Equal(t, ipv6p2, nr.DNSRewrite.Value)
		}
	})

	t.Run("refused_host", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		if assert.Len(t, dnsr, 1) {
			nr := dnsr[0]
			assert.Equal(t, dns.RcodeRefused, nr.DNSRewrite.RCode)
		}
	})

	t.Run("new_cname", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		if assert.Len(t, dnsr, 1) {
			nr := dnsr[0]
			assert.Equal(t, "othercname", nr.DNSRewrite.NewCNAME)
		}
	})

	t.Run("new_mx", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		if assert.Len(t, dnsr, 1) {
			nr := dnsr[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeMX, nr.DNSRewrite.RRType)

			mx := &rules.DNSMX{
				Exchange:   "new_mx_host",
				Preference: 32,
			}
			assert.Equal(t, mx, nr.DNSRewrite.Value)
		}
	})

	t.Run("new_txt", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		if assert.Len(t, dnsr, 1) {
			nr := dnsr[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeTXT, nr.DNSRewrite.RRType)
			assert.Equal(t, "new_txtcontent", nr.DNSRewrite.Value)
		}
	})

	t.Run("1.2.3.4.in-addr.arpa", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		if assert.Len(t, dnsr, 1) {
			nr := dnsr[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypePTR, nr.DNSRewrite.RRType)
			assert.Equal(t, "new_ptr", nr.DNSRewrite.Value)
		}
	})

	t.Run("https_record", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		if assert.Len(t, dnsr, 1) {
			nr := dnsr[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeHTTPS, nr.DNSRewrite.RRType)

			p := map[string]string{
				"alpn": "h3",
			}
			svcb := &rules.DNSSVCB{
				Params:   p,
				Target:   "https_record_host",
				Priority: 32,
			}
			assert.Equal(t, svcb, nr.DNSRewrite.Value)
		}
	})

	t.Run("svcb_record", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		if assert.Len(t, dnsr, 1) {
			nr := dnsr[0]
			assert.Equal(t, dns.RcodeSuccess, nr.DNSRewrite.RCode)
			assert.Equal(t, dns.TypeSVCB, nr.DNSRewrite.RRType)

			p := map[string]string{
				"alpn": "h3",
			}
			svcb := &rules.DNSSVCB{
				Params:   p,
				Target:   "svcb_record_host",
				Priority: 32,
			}
			assert.Equal(t, svcb, nr.DNSRewrite.Value)
		}
	})

	t.Run("https_type", func(t *testing.T) {
		r := DNSRequest{
			Hostname: path.Base(t.Name()),
			DNSType:  dns.TypeHTTPS,
		}

		res, ok := dnsEngine.MatchRequest(r)
		assert.False(t, ok)

		dnsr := res.DNSRewritesAll()
		if assert.Len(t, dnsr, 1) {
			nr := dnsr[0]
			assert.Equal(t, dns.RcodeRefused, nr.DNSRewrite.RCode)
		}

		r = DNSRequest{
			Hostname: "https_type",
			DNSType:  dns.TypeA,
		}

		_, ok = dnsEngine.MatchRequest(r)
		assert.False(t, ok)
	})

	t.Run("disable_one", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		var allowListCase *rules.NetworkRule
		dnsr := res.DNSRewritesAll()
		if assert.Len(t, dnsr, 3) {
			for _, r := range dnsr {
				if r.Whitelist {
					allowListCase = r
				}
			}
		}

		if assert.NotNil(t, allowListCase) {
			dr := allowListCase.DNSRewrite
			assert.Equal(t, dns.RcodeSuccess, dr.RCode)
			assert.Equal(t, dns.TypeA, dr.RRType)
			assert.Equal(t, ipv4p1, dr.Value)
		}
	})

	t.Run("disable_all", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		var allowListCase *rules.NetworkRule
		dnsr := res.DNSRewritesAll()
		if assert.Len(t, dnsr, 3) {
			for _, r := range dnsr {
				if r.Whitelist {
					allowListCase = r
				}
			}
		}

		if assert.NotNil(t, allowListCase) {
			assert.Equal(t, &rules.DNSRewrite{}, allowListCase.DNSRewrite)
		}
	})

	t.Run("disable_all_alt_syntax", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.False(t, ok)

		var allowListCase *rules.NetworkRule
		dnsr := res.DNSRewritesAll()
		if assert.Len(t, dnsr, 3) {
			for _, r := range dnsr {
				if r.Whitelist {
					allowListCase = r
				}
			}
		}

		if assert.NotNil(t, allowListCase) {
			assert.Equal(t, &rules.DNSRewrite{}, allowListCase.DNSRewrite)
		}
	})

	t.Run("blocked_later", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.True(t, ok)
		if assert.NotNil(t, res.NetworkRule) {
			assert.Equal(t, "||blocked_later^", res.NetworkRule.RuleText)
		}

		dnsr := res.DNSRewritesAll()
		if assert.Len(t, dnsr, 1) {
			assert.True(t, dnsr[0].Whitelist)
		}
	})

	t.Run("etc_hosts_rule", func(t *testing.T) {
		res, ok := dnsEngine.Match(path.Base(t.Name()))
		assert.True(t, ok)
		if assert.Len(t, res.HostRulesV4, 1) {
			assert.Equal(t, "127.0.0.1 etc_hosts_rule", res.HostRulesV4[0].RuleText)
		}

		dnsr := res.DNSRewritesAll()
		if assert.Len(t, dnsr, 1) {
			assert.True(t, dnsr[0].Whitelist)
		}
	})
}
