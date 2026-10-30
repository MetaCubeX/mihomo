package route

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	MDNS "github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/rules"
	RP "github.com/metacubex/mihomo/rules/provider"
	"github.com/metacubex/mihomo/rules/wrapper"
	"github.com/metacubex/mihomo/tunnel"
	D "github.com/miekg/dns"
)

func TestRuleMatchLazyDNS(t *testing.T) {
	RP.SetTunnel(tunnel.Tunnel)
	oldRules, oldProviders := tunnel.Rules(), tunnel.RuleProviders()
	oldProxies, oldProxyProviders := tunnel.Proxies(), tunnel.Providers()
	oldResolver, oldHosts, oldIPv6 := resolver.DefaultResolver, resolver.DefaultHosts, resolver.DisableIPv6
	t.Cleanup(func() {
		tunnel.UpdateRules(oldRules, nil, oldProviders)
		tunnel.UpdateProxies(oldProxies, oldProxyProviders)
		resolver.DefaultResolver, resolver.DefaultHosts, resolver.DisableIPv6 = oldResolver, oldHosts, oldIPv6
	})
	resolver.DefaultHosts = resolver.NewHosts(trie.New[resolver.HostValue]())
	resolver.DisableIPv6 = true
	tunnel.UpdateProxies(map[string]C.Proxy{"DIRECT": adapter.NewProxy(outbound.NewDirect())}, nil)

	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var queries atomic.Int32
	cancelStarted, releaseCancel := make(chan struct{}), make(chan struct{})
	var startedOnce, releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseCancel) }) }
	ready, serverDone := make(chan struct{}), make(chan error, 1)
	server := &D.Server{
		PacketConn:        packet,
		NotifyStartedFunc: func() { close(ready) },
		Handler: D.HandlerFunc(func(w D.ResponseWriter, request *D.Msg) {
			queries.Add(1)
			reply := new(D.Msg)
			reply.SetReply(request)
			name := request.Question[0].Name
			if strings.HasPrefix(name, "cancel.") {
				startedOnce.Do(func() { close(cancelStarted) })
				<-releaseCancel
			}
			if strings.HasPrefix(name, "failure.") {
				reply.Rcode = D.RcodeNameError
			} else {
				reply.Answer = []D.RR{&D.A{
					Hdr: D.RR_Header{Name: name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
					A:   net.IPv4(192, 0, 2, 9),
				}}
			}
			_ = w.WriteMsg(reply)
		}),
	}
	go func() { serverDone <- server.ActivateAndServe() }()
	select {
	case <-ready:
	case err := <-serverDone:
		_ = packet.Close()
		t.Fatalf("DNS server start: %v", err)
	}
	t.Cleanup(func() {
		release()
		_ = server.Shutdown()
		if err := <-serverDone; err != nil {
			t.Errorf("DNS server: %v", err)
		}
	})
	loaded := MDNS.NewResolver(MDNS.Config{
		Main: []MDNS.NameServer{{Net: "rcode", Addr: "refused"}},
		Policy: []MDNS.Policy{{
			Domain:      "+.rule-match.test",
			NameServers: []MDNS.NameServer{{Addr: packet.LocalAddr().String()}},
		}},
	}).Resolver
	resolver.DefaultResolver = loaded

	parse := func(tp, payload string, params ...string) C.RuleWrapper {
		rule, err := rules.ParseRule(tp, payload, "DIRECT", params, nil)
		if err != nil {
			t.Fatal(err)
		}
		return wrapper.NewRuleWrapper(rule)
	}
	fallback := parse("MATCH", "")
	ipRule := parse("IP-CIDR", "192.0.2.0/24")
	noResolve := parse("IP-CIDR", "192.0.2.0/24", "no-resolve")
	disabled := parse("IP-CIDR", "192.0.2.0/24")
	disabled.SetDisabled(true)
	providers := map[string]P.RuleProvider{
		"ip":        RP.NewInlineProvider("ip", P.IPCIDR, []string{"192.0.2.0/24"}, rules.ParseRule),
		"classical": RP.NewInlineProvider("classical", P.Classical, []string{"IP-CIDR,192.0.2.0/24"}, rules.ParseRule),
		"source":    RP.NewInlineProvider("source", P.Classical, []string{"SRC-IP-CIDR,192.0.2.0/24"}, rules.ParseRule),
	}
	for index, tc := range []struct {
		name     string
		rules    []C.Rule
		query    string
		complete bool
		attempt  bool
		ip       string
		missing  string
		index    int
	}{
		{name: "offline", rules: []C.Rule{ipRule}, missing: "ip"},
		{name: "explicit offline", rules: []C.Rule{ipRule}, query: "&resolve=false", missing: "ip"},
		{name: "lazy online", rules: []C.Rule{ipRule}, query: "&resolve=true", complete: true, attempt: true, ip: "192.0.2.9"},
		{name: "early domain offline", rules: []C.Rule{parse("DOMAIN-SUFFIX", "rule-match.test"), ipRule}, complete: true},
		{name: "early domain", rules: []C.Rule{parse("DOMAIN-SUFFIX", "rule-match.test"), ipRule}, query: "&resolve=true", complete: true},
		{name: "supplied IP", rules: []C.Rule{ipRule}, query: "&resolve=true&ip=192.0.2.7", complete: true, ip: "192.0.2.7"},
		{name: "no resolve", rules: []C.Rule{noResolve}, query: "&resolve=true", missing: "ip"},
		{name: "no resolve supplied", rules: []C.Rule{noResolve}, query: "&resolve=true&ip=192.0.2.8", complete: true, ip: "192.0.2.8"},
		{name: "source missing", rules: []C.Rule{parse("SRC-IP-CIDR", "192.0.2.0/24")}, query: "&resolve=true", missing: "source-ip"},
		{name: "source supplied", rules: []C.Rule{parse("SRC-IP-CIDR", "192.0.2.0/24")}, query: "&resolve=true&source-ip=192.0.2.7", complete: true},
		{name: "disabled", rules: []C.Rule{disabled}, query: "&resolve=true", complete: true, index: 1},
		{name: "IP provider", rules: []C.Rule{parse("RULE-SET", "ip")}, query: "&resolve=true", complete: true, attempt: true, ip: "192.0.2.9"},
		{name: "classical provider", rules: []C.Rule{parse("RULE-SET", "classical")}, query: "&resolve=true", complete: true, attempt: true, ip: "192.0.2.9"},
		{name: "IP provider no resolve", rules: []C.Rule{parse("RULE-SET", "ip", "no-resolve")}, query: "&resolve=true", missing: "ip"},
		{name: "classical no resolve", rules: []C.Rule{parse("RULE-SET", "classical", "no-resolve")}, query: "&resolve=true", missing: "ip"},
		{name: "IP provider source missing", rules: []C.Rule{parse("RULE-SET", "ip", "src")}, query: "&resolve=true", missing: "source-ip"},
		{name: "IP provider source supplied", rules: []C.Rule{parse("RULE-SET", "ip", "src")}, query: "&resolve=true&source-ip=192.0.2.7", complete: true},
		{name: "classical source missing", rules: []C.Rule{parse("RULE-SET", "classical", "src")}, query: "&resolve=true", missing: "source-ip"},
		{name: "classical source supplied", rules: []C.Rule{parse("RULE-SET", "classical", "src")}, query: "&resolve=true&source-ip=192.0.2.7", complete: true},
		{name: "swapped source uses destination", rules: []C.Rule{parse("RULE-SET", "source", "src")}, query: "&resolve=true&ip=192.0.2.7", complete: true, ip: "192.0.2.7"},
		{name: "swapped source never resolves destination", rules: []C.Rule{parse("RULE-SET", "source", "src")}, query: "&resolve=true&source-ip=192.0.2.7", missing: "ip"},
		{name: "nested OR", rules: []C.Rule{parse("OR", "((DOMAIN,other.test),(IP-CIDR,192.0.2.0/24))")}, query: "&resolve=true", complete: true, attempt: true, ip: "192.0.2.9"},
		{name: "nested AND short circuit", rules: []C.Rule{parse("AND", "((DOMAIN,other.test),(IP-CIDR,192.0.2.0/24))")}, query: "&resolve=true", complete: true, index: 1},
		{name: "nested missing process stops DNS", rules: []C.Rule{parse("OR", "((PROCESS-NAME,curl),(IP-CIDR,192.0.2.0/24))")}, query: "&resolve=true", missing: "process"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tunnel.UpdateRules(append(tc.rules, fallback), nil, providers)
			before := queries.Load()
			w := httptest.NewRecorder()
			query := fmt.Sprintf("domain=case-%d.rule-match.test%s", index, tc.query)
			ruleRouter().ServeHTTP(w, httptest.NewRequest("GET", "/match?"+query, nil))
			var result tunnel.RuleMatchResult
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
				t.Fatalf("response %d: %s", w.Code, w.Body)
			}
			if result.Complete != tc.complete || result.IP != tc.ip || result.DNS.Attempted != tc.attempt || result.DNS.Enabled != strings.Contains(tc.query, "resolve=true") || result.DNS.Error != "" {
				t.Fatalf("unexpected diagnostic: %+v", result)
			}
			if tc.complete {
				if result.Policy != "DIRECT" || result.Rule == nil || result.Rule.Index != tc.index || len(result.Missing) != 0 {
					t.Fatalf("unexpected winner: %+v", result)
				}
			} else if result.Policy != "" || result.Rule == nil || result.Rule.Index != 0 || len(result.Missing) != 1 || result.Missing[0] != tc.missing {
				t.Fatalf("unexpected incomplete result: %+v", result)
			}
			wantQueries := int32(0)
			if tc.attempt {
				wantQueries = 1
			}
			if queries.Load()-before != wantQueries {
				t.Fatalf("upstream requests = %d, want %d", queries.Load()-before, wantQueries)
			}
			for _, rule := range append(tc.rules, fallback) {
				wrapped := rule.(C.RuleWrapper)
				if wrapped.HitCount() != 0 || wrapped.MissCount() != 0 {
					t.Fatal("diagnostic changed wrapper statistics")
				}
			}
		})
	}

	t.Run("nested subrule", func(t *testing.T) {
		children := map[string][]C.Rule{"child": {ipRule, fallback}}
		subrule, err := rules.ParseRule("SUB-RULE", "(DOMAIN-SUFFIX,rule-match.test)", "child", nil, children)
		if err != nil {
			t.Fatal(err)
		}
		tunnel.UpdateRules([]C.Rule{wrapper.NewRuleWrapper(subrule), fallback}, children, nil)
		before := queries.Load()
		w := httptest.NewRecorder()
		ruleRouter().ServeHTTP(w, httptest.NewRequest("GET", "/match?domain=nested.rule-match.test&resolve=true", nil))
		var result tunnel.RuleMatchResult
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if !result.Complete || result.Policy != "DIRECT" || result.IP != "192.0.2.9" || !result.DNS.Attempted || len(result.SubRules) != 1 || result.SubRules[0].Name != "child" || result.SubRules[0].Index != 0 || queries.Load()-before != 1 {
			t.Fatalf("nested lazy DNS result: %+v", result)
		}
		if ipRule.HitCount() != 0 || ipRule.MissCount() != 0 {
			t.Fatal("nested DNS diagnostic changed statistics")
		}
	})

	t.Run("DNS error cannot match NOT or fallback", func(t *testing.T) {
		tunnel.UpdateRules([]C.Rule{parse("NOT", "((IP-CIDR,192.0.2.0/24))"), fallback}, nil, nil)
		w := httptest.NewRecorder()
		ruleRouter().ServeHTTP(w, httptest.NewRequest("GET", "/match?domain=failure.rule-match.test&resolve=true", nil))
		var result tunnel.RuleMatchResult
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if w.Code != 200 || result.Complete || result.Policy != "" || result.IP != "" || !result.DNS.Attempted || result.DNS.Error == "" || result.Rule == nil || result.Rule.Index != 0 || len(result.Missing) != 1 || result.Missing[0] != "ip" {
			t.Fatalf("DNS error must be incomplete: %+v", result)
		}
	})

	t.Run("request cancellation", func(t *testing.T) {
		tunnel.UpdateRules([]C.Rule{ipRule, fallback}, nil, nil)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		w := httptest.NewRecorder()
		request := httptest.NewRequest("GET", "/match?domain=cancel.rule-match.test&resolve=true", nil).WithContext(ctx)
		done := make(chan struct{})
		go func() {
			ruleRouter().ServeHTTP(w, request)
			close(done)
		}()
		select {
		case <-cancelStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("resolver did not query test upstream")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("HTTP cancellation did not stop diagnostic")
		}
		var result tunnel.RuleMatchResult
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Complete || result.Policy != "" || result.IP != "" || !result.DNS.Attempted || result.DNS.Error != context.Canceled.Error() || len(result.Missing) != 1 || result.Missing[0] != "ip" {
			t.Fatalf("cancellation must be incomplete: %+v", result)
		}
		// The loaded resolver shares upstream exchanges. Release and join the
		// exchange rather than leaving its background singleflight running.
		release()
		joinCtx, joinCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer joinCancel()
		if _, err := loaded.LookupIPv4(joinCtx, "cancel.rule-match.test"); err != nil {
			t.Fatal(err)
		}
	})
}
