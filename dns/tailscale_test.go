package dns

import (
	"testing"

	"github.com/metacubex/mihomo/component/tailnet"

	D "github.com/miekg/dns"
)

func TestResolverMatchesTailnetMagicDNSPolicy(t *testing.T) {
	const proxyName = "magicdns-policy-test"
	tailnet.SetSearchDomains(proxyName, []string{"tailnet.test"})
	t.Cleanup(func() { tailnet.RemoveSearchDomains(proxyName) })

	query := new(D.Msg)
	query.SetQuestion(D.Fqdn("newvbox.tailnet.test"), D.TypeA)

	matched := (&Resolver{}).matchPolicy(query)
	if len(matched) != 1 {
		t.Fatalf("matched %d clients, want 1", len(matched))
	}
	if got, want := matched[0].Address(), "tailscale://"+proxyName; got != want {
		t.Fatalf("matched client = %q, want %q", got, want)
	}
}
