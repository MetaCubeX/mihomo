package dns

import (
	"context"

	D "github.com/miekg/dns"

	"github.com/Dreamacro/clash/common/cache"
	"github.com/Dreamacro/clash/component/dhcp"
	"github.com/Dreamacro/clash/component/resolver"
)

const SystemDNSPlaceholder = "system"

var systemResolver *Resolver
var isolateHandler handler

var _ dnsClient = (*dhcpClient)(nil)

type dhcpClient struct {
	enable bool
}

func (d *dhcpClient) Address() string {
	return SystemDNSPlaceholder
}

func (d *dhcpClient) Exchange(m *D.Msg) (msg *D.Msg, err error) {
	return d.ExchangeContext(context.Background(), m)
}

func (d *dhcpClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	if s := systemResolver; s != nil {
		return s.ExchangeContext(ctx, m)
	}

	return nil, dhcp.ErrNotFound
}

func ServeDNSWithDefaultServer(msg *D.Msg) (*D.Msg, error) {
	if h := isolateHandler; h != nil {
		return handlerWithContext(context.Background(), h, msg)
	}

	return nil, D.ErrTime
}

func FlushCacheWithDefaultResolver() {
	if r := resolver.DefaultResolver; r != nil {
		r.(*Resolver).lruCache = cache.New[string, *D.Msg](cache.WithSize[string, *D.Msg](4096), cache.WithStale[string, *D.Msg](true))
	}
}

func UpdateSystemDNS(addr []string) {
	if len(addr) == 0 {
		systemResolver = nil
	}

	ns := make([]NameServer, 0, len(addr))
	for _, d := range addr {
		ns = append(ns, NameServer{Addr: d})
	}

	systemResolver = NewResolver(Config{Main: ns})
}

func UpdateIsolateHandler(resolver *Resolver, mapper *ResolverEnhancer) {
	if resolver == nil {
		isolateHandler = nil

		return
	}

	isolateHandler = NewHandler(resolver, mapper)
}

func newDHCPClient(ifaceName string) *dhcpClient {
	return &dhcpClient{enable: ifaceName == SystemDNSPlaceholder}
}
