package proxy

import (
	"net"
	"testing"

	"github.com/AdguardTeam/gomitmproxy"
	"github.com/stretchr/testify/assert"
)

func TestConfigStringProxyAuth(t *testing.T) {
	t.Parallel()

	const (
		username = "proxy-user"
		password = "proxy-password"
	)

	conf := &Config{
		ProxyConfig: gomitmproxy.Config{
			ListenAddr: &net.TCPAddr{},
			Username:   username,
			Password:   password,
		},
	}

	got := conf.String()
	assert.Contains(t, got, "Proxy auth: enabled\n")
	assert.NotContains(t, got, username)
	assert.NotContains(t, got, password)
}
