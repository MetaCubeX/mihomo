package dns

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	D "github.com/miekg/dns"
)

type tailscaleDNSClient struct {
	name string
}

type tailscaleResolverEntry struct {
	id     uint64
	client dnsClient
}

var (
	tailscaleResolverID atomic.Uint64
	tailscaleResolverMu sync.RWMutex
	tailscaleResolvers  = map[string]tailscaleResolverEntry{}
)

var _ dnsClient = (*tailscaleDNSClient)(nil)

func RegisterTailscaleDnsClient(name string, client dnsClient) func() {
	id := tailscaleResolverID.Add(1)
	tailscaleResolverMu.Lock()
	tailscaleResolvers[name] = tailscaleResolverEntry{
		id:     id,
		client: client,
	}
	tailscaleResolverMu.Unlock()

	return func() {
		tailscaleResolverMu.Lock()
		if entry, ok := tailscaleResolvers[name]; ok && entry.id == id {
			delete(tailscaleResolvers, name)
		}
		tailscaleResolverMu.Unlock()
	}
}

func newTailscaleClient(name string) *tailscaleDNSClient {
	return &tailscaleDNSClient{name: name}
}

func (c *tailscaleDNSClient) Address() string {
	return "tailscale://" + c.name
}

func (c *tailscaleDNSClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	tailscaleResolverMu.RLock()
	entry, ok := tailscaleResolvers[c.name]
	tailscaleResolverMu.RUnlock()
	if !ok || entry.client == nil {
		return nil, fmt.Errorf("proxy %q does not provide Tailscale DNS", c.name)
	}
	return entry.client.ExchangeContext(ctx, m)
}

func (c *tailscaleDNSClient) ResetConnection() {}
