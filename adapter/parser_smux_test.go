//go:build !no_easytier

package adapter_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/dns"

	D "github.com/miekg/dns"
)

// An outbound that registers process-wide state in its constructor must be
// closed when ParseProxy fails later, otherwise that state leaks. EasyTier
// registers its DNS client by name on construction and removes it in Close.
func TestParseProxyClosesOutboundOnSmuxError(t *testing.T) {
	for _, tc := range []struct {
		name string
		smux map[string]any
	}{
		{"decode", map[string]any{"enabled": "not-a-bool"}},
		{"construct", map[string]any{"enabled": true, "protocol": "not-a-protocol"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := "smux-" + tc.name
			proxy, err := adapter.ParseProxy(map[string]any{
				"name":         name,
				"type":         "easytier",
				"network-name": "test",
				"peers":        []string{"tcp://192.0.2.1:11010"},
				"smux":         tc.smux,
			})
			if err == nil {
				_ = proxy.Close()
				t.Fatal("expected invalid smux options to fail")
			}

			resolver := dns.NewResolver(dns.Config{
				Main: []dns.NameServer{{Net: "easytier", Addr: name}},
			})
			query := new(D.Msg).SetQuestion("host.example.", D.TypeA)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err = resolver.ExchangeContext(ctx, query)
			if err == nil || !strings.Contains(err.Error(), "does not provide EasyTier DNS") {
				t.Fatalf("failed parse must leave no EasyTier DNS client registered, got err=%v", err)
			}
		})
	}
}
