package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

const applyRulesBase = `
proxies:
  - {name: hk, type: socks5, server: 127.0.0.1, port: 1080}
proxy-groups:
  - {name: Proxy, type: select, proxies: [hk, DIRECT]}
rule-providers:
  local: {type: file, behavior: domain, format: text, path: ./local.txt}
`

// startRules sets up running proxies and rules the way ApplyConfig does,
// without listeners.
func startRules(t *testing.T, rules string) {
	t.Helper()
	dir := t.TempDir()
	C.SetHomeDir(dir)
	if err := os.WriteFile(filepath.Join(dir, "local.txt"), []byte("example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseWithBytes([]byte(applyRulesBase + rules))
	if err != nil {
		t.Fatal(err)
	}
	updateProxies(cfg.Proxies, cfg.Providers)
	loadProvider(cfg.RuleProviders)
	updateRules(cfg.Rules, cfg.SubRules, cfg.RuleProviders)
	t.Cleanup(func() { updateRules(nil, nil, nil) })
}

// firstRule returns "type,payload → proxy" for the first rule a host hits.
func firstRule(host string) string {
	metadata := &C.Metadata{Host: host, DstPort: 443, NetWork: C.TCP}
	for _, rule := range tunnel.Rules() {
		if ok, adapter := rule.Match(metadata, C.RuleMatchHelper{}); ok {
			return rule.RuleType().String() + "," + rule.Payload() + " → " + adapter
		}
	}
	return "no rule"
}

func TestApplyRulesKeepsRuleSetsMatching(t *testing.T) {
	startRules(t, "rules:\n  - RULE-SET,local,Proxy\n  - MATCH,DIRECT\n")

	cfg, err := ParseWithBytes([]byte(applyRulesBase +
		"rules:\n  - DOMAIN,new.example,Proxy\n  - RULE-SET,local,Proxy\n  - MATCH,DIRECT\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyRules(cfg); err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]string{
		"new.example":   "Domain,new.example → Proxy",
		"example.com":   "RuleSet,local → Proxy",
		"other.example": "Match, → DIRECT",
	} {
		if got := firstRule(host); got != want {
			t.Errorf("%s: got %s, want %s", host, got, want)
		}
	}
}

func TestApplyRulesRejectsProxyNotRunning(t *testing.T) {
	startRules(t, "rules:\n  - RULE-SET,local,Proxy\n  - MATCH,DIRECT\n")

	cfg, err := ParseWithBytes([]byte(strings.Replace(applyRulesBase,
		"proxy-groups:\n", "proxy-groups:\n  - {name: Netflix, type: select, proxies: [hk]}\n", 1) +
		"rules:\n  - DOMAIN,netflix.com,Netflix\n  - MATCH,DIRECT\n"))
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyRules(cfg)
	if err == nil || !strings.Contains(err.Error(), "proxy [Netflix] is not running") {
		t.Fatalf("want an error about Netflix, got %v", err)
	}
	if got := firstRule("example.com"); got != "RuleSet,local → Proxy" {
		t.Errorf("running rules changed after a rejected update: %s", got)
	}
}
