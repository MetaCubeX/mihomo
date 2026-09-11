package tunnel

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type resettingAdapter struct {
	C.ProxyAdapter
	resets int
}

func (a *resettingAdapter) ResetSession(string) { a.resets++ }

type proxyOf struct {
	C.Proxy
	adapter C.ProxyAdapter
}

func (p proxyOf) Adapter() C.ProxyAdapter { return p.adapter }

type providerOf struct {
	P.ProxyProvider
	proxies []C.Proxy
}

func (p providerOf) Proxies() []C.Proxy { return p.proxies }

func TestResetOutboundSessionsVisitsEveryResetterOnce(t *testing.T) {
	quic := &resettingAdapter{}
	plain := &struct{ C.ProxyAdapter }{}
	shared := proxyOf{adapter: quic}

	oldProxies, oldProviders := Proxies(), Providers()
	t.Cleanup(func() { UpdateProxies(oldProxies, oldProviders) })
	UpdateProxies(map[string]C.Proxy{
		"quic":  shared,
		"alias": shared,
		"tcp":   proxyOf{adapter: plain},
	}, map[string]P.ProxyProvider{
		"p": providerOf{proxies: []C.Proxy{shared, proxyOf{adapter: plain}}},
	})

	if got := ResetOutboundSessions("test"); got != 1 {
		t.Fatalf("reset %d outbounds, want 1", got)
	}
	if quic.resets != 1 {
		t.Fatalf("the QUIC outbound was reset %d times, want once", quic.resets)
	}
}
