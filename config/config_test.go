package config

import (
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/assert"
)

func TestValidateDialerProxies_ValidReference(t *testing.T) {
	proxies := make(map[string]C.Proxy)

	// create base proxy
	baseProxy, _ := outbound.NewSocks5(outbound.Socks5Option{
		BasicOption: outbound.BasicOption{},
		Name:        "base-proxy",
		Server:      "127.0.0.1",
		Port:        1080,
	})
	proxies["base-proxy"] = adapter.NewProxy(baseProxy)

	// create proxy with valid dialer-proxy reference
	proxyWithDialer, _ := outbound.NewSocks5(outbound.Socks5Option{
		BasicOption: outbound.BasicOption{
			DialerProxy: "base-proxy",
		},
		Name:   "proxy-with-dialer",
		Server: "127.0.0.1",
		Port:   1081,
	})
	proxies["proxy-with-dialer"] = adapter.NewProxy(proxyWithDialer)

	// add built-in proxies
	proxies["DIRECT"] = adapter.NewProxy(outbound.NewDirect())
	proxies["REJECT"] = adapter.NewProxy(outbound.NewReject())

	err := validateDialerProxies(proxies)
	assert.NoError(t, err, "valid dialer-proxy reference should pass validation")
}

func TestValidateDialerProxies_NotFoundReference(t *testing.T) {
	proxies := make(map[string]C.Proxy)

	// create proxy with non-existent dialer-proxy reference
	proxyWithDialer, _ := outbound.NewSocks5(outbound.Socks5Option{
		BasicOption: outbound.BasicOption{
			DialerProxy: "non-existent-proxy",
		},
		Name:   "proxy-with-dialer",
		Server: "127.0.0.1",
		Port:   1081,
	})
	proxies["proxy-with-dialer"] = adapter.NewProxy(proxyWithDialer)

	// add built-in proxies
	proxies["DIRECT"] = adapter.NewProxy(outbound.NewDirect())
	proxies["REJECT"] = adapter.NewProxy(outbound.NewReject())

	err := validateDialerProxies(proxies)
	assert.Error(t, err, "non-existent dialer-proxy reference should fail validation")
	assert.Contains(t, err.Error(), "not found", "error message should indicate proxy not found")
}

func TestValidateDialerProxies_CircularDependency(t *testing.T) {
	proxies := make(map[string]C.Proxy)

	// create proxy A that references B
	proxyA, _ := outbound.NewSocks5(outbound.Socks5Option{
		BasicOption: outbound.BasicOption{
			DialerProxy: "proxy-b",
		},
		Name:   "proxy-a",
		Server: "127.0.0.1",
		Port:   1081,
	})
	proxies["proxy-a"] = adapter.NewProxy(proxyA)

	// create proxy B that references C
	proxyB, _ := outbound.NewSocks5(outbound.Socks5Option{
		BasicOption: outbound.BasicOption{
			DialerProxy: "proxy-c",
		},
		Name:   "proxy-b",
		Server: "127.0.0.1",
		Port:   1082,
	})
	proxies["proxy-b"] = adapter.NewProxy(proxyB)

	// create proxy C that references A (creates cycle)
	proxyC, _ := outbound.NewSocks5(outbound.Socks5Option{
		BasicOption: outbound.BasicOption{
			DialerProxy: "proxy-a",
		},
		Name:   "proxy-c",
		Server: "127.0.0.1",
		Port:   1083,
	})
	proxies["proxy-c"] = adapter.NewProxy(proxyC)

	// add built-in proxies
	proxies["DIRECT"] = adapter.NewProxy(outbound.NewDirect())
	proxies["REJECT"] = adapter.NewProxy(outbound.NewReject())

	err := validateDialerProxies(proxies)
	assert.Error(t, err, "circular dialer-proxy dependency should fail validation")
	assert.Contains(t, err.Error(), "circular", "error message should indicate circular dependency")
}

func TestValidateDialerProxies_ComplexChain(t *testing.T) {
	proxies := make(map[string]C.Proxy)

	// create a valid chain: proxy-d -> proxy-c -> proxy-b -> proxy-a
	proxyA, _ := outbound.NewSocks5(outbound.Socks5Option{
		BasicOption: outbound.BasicOption{},
		Name:        "proxy-a",
		Server:      "127.0.0.1",
		Port:        1080,
	})
	proxies["proxy-a"] = adapter.NewProxy(proxyA)

	proxyB, _ := outbound.NewSocks5(outbound.Socks5Option{
		BasicOption: outbound.BasicOption{
			DialerProxy: "proxy-a",
		},
		Name:   "proxy-b",
		Server: "127.0.0.1",
		Port:   1081,
	})
	proxies["proxy-b"] = adapter.NewProxy(proxyB)

	proxyC, _ := outbound.NewSocks5(outbound.Socks5Option{
		BasicOption: outbound.BasicOption{
			DialerProxy: "proxy-b",
		},
		Name:   "proxy-c",
		Server: "127.0.0.1",
		Port:   1082,
	})
	proxies["proxy-c"] = adapter.NewProxy(proxyC)

	proxyD, _ := outbound.NewSocks5(outbound.Socks5Option{
		BasicOption: outbound.BasicOption{
			DialerProxy: "proxy-c",
		},
		Name:   "proxy-d",
		Server: "127.0.0.1",
		Port:   1083,
	})
	proxies["proxy-d"] = adapter.NewProxy(proxyD)

	// add built-in proxies
	proxies["DIRECT"] = adapter.NewProxy(outbound.NewDirect())
	proxies["REJECT"] = adapter.NewProxy(outbound.NewReject())

	err := validateDialerProxies(proxies)
	assert.NoError(t, err, "valid complex dialer-proxy chain should pass validation")
}

func TestValidateDialerProxies_BuiltinProxiesSkipped(t *testing.T) {
	proxies := make(map[string]C.Proxy)

	// add built-in proxies (should be skipped in validation)
	proxies["DIRECT"] = adapter.NewProxy(outbound.NewDirect())
	proxies["REJECT"] = adapter.NewProxy(outbound.NewReject())
	proxies["REJECT-DROP"] = adapter.NewProxy(outbound.NewRejectDrop())
	proxies["COMPATIBLE"] = adapter.NewProxy(outbound.NewCompatible())
	proxies["PASS"] = adapter.NewProxy(outbound.NewPass())

	err := validateDialerProxies(proxies)
	assert.NoError(t, err, "built-in proxies should be skipped in validation")
}

func TestValidateDialerProxies_EmptyDialerProxy(t *testing.T) {
	proxies := make(map[string]C.Proxy)

	// create proxy without dialer-proxy
	proxy, _ := outbound.NewSocks5(outbound.Socks5Option{
		BasicOption: outbound.BasicOption{},
		Name:        "simple-proxy",
		Server:      "127.0.0.1",
		Port:        1080,
	})
	proxies["simple-proxy"] = adapter.NewProxy(proxy)

	// add built-in proxies
	proxies["DIRECT"] = adapter.NewProxy(outbound.NewDirect())
	proxies["REJECT"] = adapter.NewProxy(outbound.NewReject())

	err := validateDialerProxies(proxies)
	assert.NoError(t, err, "proxy without dialer-proxy should pass validation")
}

func TestValidateDialerProxies_SelfReference(t *testing.T) {
	proxies := make(map[string]C.Proxy)

	// create proxy that references itself
	proxy, _ := outbound.NewSocks5(outbound.Socks5Option{
		BasicOption: outbound.BasicOption{
			DialerProxy: "self-proxy",
		},
		Name:   "self-proxy",
		Server: "127.0.0.1",
		Port:   1080,
	})
	proxies["self-proxy"] = adapter.NewProxy(proxy)

	// add built-in proxies
	proxies["DIRECT"] = adapter.NewProxy(outbound.NewDirect())
	proxies["REJECT"] = adapter.NewProxy(outbound.NewReject())

	err := validateDialerProxies(proxies)
	assert.Error(t, err, "self-referencing dialer-proxy should fail validation")
	assert.Contains(t, err.Error(), "circular", "error message should indicate circular dependency")
}
