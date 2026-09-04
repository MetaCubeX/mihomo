package adapter_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	RC "github.com/metacubex/mihomo/rules/common"
	"github.com/metacubex/mihomo/tunnel"
)

func TestURLTestRematch(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("method = %s, want HEAD", r.Method)
		}
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() {
		tunnel.UpdateProxies(nil, nil)
		tunnel.UpdateRules(nil, nil, nil)
	})

	for _, target := range []string{"sub-rule", "rematch-name", "both"} {
		t.Run(target, func(t *testing.T) {
			mapping := map[string]any{"name": "rematch", "type": "rematch"}
			if target != "rematch-name" {
				mapping["target-sub-rule"] = "route"
			}
			if target != "sub-rule" {
				mapping["target-rematch-name"] = "selected"
			}
			rematch, err := adapter.ParseProxy(mapping)
			if err != nil {
				t.Fatal(err)
			}
			direct := adapter.NewProxy(outbound.NewDirect())
			reject := adapter.NewProxy(outbound.NewReject())
			selected := rematchSelector(t, "selected", rematch)
			nested := rematchSelector(t, "nested", selected)
			tunnel.UpdateProxies(map[string]C.Proxy{
				"DIRECT": direct, "REJECT": reject, "rematch": rematch,
				"selected": selected, "nested": nested,
			}, nil)
			tcpRule, err := RC.NewNetworkType("TCP", "DIRECT")
			if err != nil {
				t.Fatal(err)
			}
			nameRule, err := RC.NewRematchName("selected", "DIRECT")
			if err != nil {
				t.Fatal(err)
			}
			route := []C.Rule{tcpRule, RC.NewMatch("REJECT")}
			if target == "both" {
				route = []C.Rule{nameRule, RC.NewMatch("REJECT")}
			}
			tunnel.UpdateRules([]C.Rule{nameRule, RC.NewMatch("REJECT")}, map[string][]C.Rule{"route": route}, nil)

			for _, proxy := range []C.Proxy{rematch, selected, nested, direct} {
				t.Run(proxy.Name(), func(t *testing.T) {
					before := requests.Load()
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					if _, err := proxy.URLTest(ctx, server.URL, nil); err != nil {
						t.Fatalf("URLTest: %v", err)
					}
					if got := requests.Load() - before; got != 1 {
						t.Fatalf("HTTP requests = %d, want 1", got)
					}
					if !proxy.AliveForTestUrl(server.URL) {
						t.Fatal("successful rematch URL test marked the proxy unhealthy")
					}
				})
			}
		})
	}
}

func TestURLTestRematchRouting(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	oldMode := tunnel.Mode()
	t.Cleanup(func() {
		tunnel.SetMode(oldMode)
		tunnel.UpdateProxies(nil, nil)
		tunnel.UpdateRules(nil, nil, nil)
	})
	for _, mode := range []tunnel.TunnelMode{tunnel.Rule, tunnel.Global, tunnel.Direct} {
		t.Run(mode.String(), func(t *testing.T) {
			tunnel.SetMode(mode)
			for _, tc := range []struct {
				name   string
				target string
				second string
				want   string
			}{
				{name: "nested-exit", target: "exit"},
				{name: "multiple-rematches", target: "second", second: "exit"},
				{name: "self-cycle", target: "first", want: "rematch cycle"},
				{name: "two-node-cycle", target: "second", second: "first", want: "rematch cycle"},
				{name: "reject", target: "REJECT", want: "any error"},
				{name: "no-match", target: "missing", want: "any error"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					first, err := adapter.ParseProxy(map[string]any{"name": "first", "type": "rematch", "target-sub-rule": "first-rules"})
					if err != nil {
						t.Fatal(err)
					}
					second, err := adapter.ParseProxy(map[string]any{"name": "second", "type": "rematch", "target-sub-rule": "second-rules"})
					if err != nil {
						t.Fatal(err)
					}
					reject := adapter.NewProxy(outbound.NewReject())
					exit := rematchSelector(t, "exit", adapter.NewProxy(outbound.NewDirect()))
					tunnel.UpdateProxies(map[string]C.Proxy{
						"first": first, "second": second, "exit": exit,
						"GLOBAL": reject, "DIRECT": reject, "REJECT": reject,
					}, nil)
					tunnel.UpdateRules([]C.Rule{RC.NewMatch("REJECT")}, map[string][]C.Rule{
						"first-rules": {RC.NewMatch(tc.target)}, "second-rules": {RC.NewMatch(tc.second)},
					}, nil)
					before := requests.Load()
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					_, err = first.URLTest(ctx, server.URL, nil)
					if tc.want != "" {
						if err == nil || (tc.want != "any error" && !strings.Contains(err.Error(), tc.want)) {
							t.Fatalf("URLTest error = %v, want %q", err, tc.want)
						}
						if requests.Load() != before || first.AliveForTestUrl(server.URL) {
							t.Fatal("invalid route reached HTTP server or was marked healthy")
						}
					} else if err != nil || requests.Load()-before != 1 || !first.AliveForTestUrl(server.URL) {
						t.Fatalf("valid route failed: error=%v requests=%d", err, requests.Load()-before)
					}
				})
			}
		})
	}
}

func TestURLTestRematchDNSCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	oldResolver := resolver.DefaultResolver
	// Cancel once rule matching starts DNS. A lost parent context would wait
	// for the core's DNS timeout and then fall through to the rejecting rule.
	resolver.DefaultResolver = &cancelingResolver{cancel: cancel}
	t.Cleanup(func() {
		resolver.DefaultResolver = oldResolver
		tunnel.UpdateProxies(nil, nil)
		tunnel.UpdateRules(nil, nil, nil)
	})
	rematch, err := adapter.ParseProxy(map[string]any{"name": "rematch", "type": "rematch", "target-sub-rule": "route"})
	if err != nil {
		t.Fatal(err)
	}
	ipRule, err := RC.NewIPCIDR("127.0.0.0/8", "REJECT")
	if err != nil {
		t.Fatal(err)
	}
	tunnel.UpdateProxies(map[string]C.Proxy{"REJECT": adapter.NewProxy(outbound.NewReject())}, nil)
	tunnel.UpdateRules(nil, map[string][]C.Rule{"route": {ipRule, RC.NewMatch("REJECT")}}, nil)
	_, err = rematch.URLTest(ctx, "http://rematch-url-test.invalid", nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("URLTest error = %v, want context.Canceled", err)
	}
}

type cancelingResolver struct {
	resolver.Resolver
	cancel context.CancelFunc
}

func (r *cancelingResolver) Invalid() bool { return true }

func (r *cancelingResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	r.cancel()
	<-ctx.Done()
	return nil, ctx.Err()
}

func rematchSelector(t *testing.T, name string, proxy C.Proxy) C.Proxy {
	t.Helper()
	proxies := []C.Proxy{proxy}
	hc := provider.NewHealthCheck(proxies, "", 1000, 0, true, nil)
	pd, err := provider.NewCompatibleProvider(name, proxies, hc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pd.Close() })
	selector, err := outboundgroup.NewSelector(outboundgroup.GroupCommonOption{Name: name}, outboundgroup.SelectorOption{}, proxy, []P.ProxyProvider{pd})
	if err != nil {
		t.Fatal(err)
	}
	return adapter.NewProxy(selector)
}
