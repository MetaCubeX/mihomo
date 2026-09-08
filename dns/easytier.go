package dns

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	D "github.com/miekg/dns"
)

type easyTierDNSClient struct {
	name string
}

type easyTierResolverEntry struct {
	id     uint64
	client dnsClient
}

var (
	easyTierResolverID atomic.Uint64
	easyTierResolverMu sync.RWMutex
	easyTierResolvers  = map[string]easyTierResolverEntry{}
)

var _ dnsClient = (*easyTierDNSClient)(nil)

func RegisterEasyTierDnsClient(name string, client dnsClient) func() {
	id := easyTierResolverID.Add(1)
	easyTierResolverMu.Lock()
	easyTierResolvers[name] = easyTierResolverEntry{
		id:     id,
		client: client,
	}
	easyTierResolverMu.Unlock()

	return func() {
		easyTierResolverMu.Lock()
		if entry, ok := easyTierResolvers[name]; ok && entry.id == id {
			delete(easyTierResolvers, name)
		}
		easyTierResolverMu.Unlock()
	}
}

func newEasyTierClient(name string) *easyTierDNSClient {
	return &easyTierDNSClient{name: name}
}

func (c *easyTierDNSClient) Address() string {
	return "easytier://" + c.name
}

func (c *easyTierDNSClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	easyTierResolverMu.RLock()
	entry, ok := easyTierResolvers[c.name]
	easyTierResolverMu.RUnlock()
	if !ok || entry.client == nil {
		return nil, fmt.Errorf("proxy %q does not provide EasyTier DNS", c.name)
	}
	return entry.client.ExchangeContext(ctx, m)
}

func (c *easyTierDNSClient) ResetConnection() {}
