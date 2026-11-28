package provider

import (
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"testing"
)

type backgroundTestProxy struct {
	*outbound.Base
	starts int
}

func (p *backgroundTestProxy) StartBackground() { p.starts++ }

func TestBackgroundProxyProviderLifecycle(t *testing.T) {
	p := &backgroundTestProxy{Base: outbound.NewBase(outbound.BaseOption{Name: "background"})}
	proxies := []C.Proxy{adapter.NewProxy(outbound.NewAutoCloseProxyAdapter(p))}
	hc := NewHealthCheck(proxies, "", 5000, 0, true, nil)
	pd, err := NewCompatibleProvider("test", proxies, hc)
	if err != nil {
		t.Fatal(err)
	}
	defer pd.Close()
	if p.starts != 0 {
		t.Fatal("constructing a provider started network activity")
	}
	if err := pd.Initial(); err != nil {
		t.Fatal(err)
	}
	if p.starts != 1 {
		t.Fatalf("background startup lost through adapter wrapper: %d", p.starts)
	}
	pd.setProxies(proxies)
	if p.starts != 2 {
		t.Fatal("updated provider did not start its background proxies")
	}
}
