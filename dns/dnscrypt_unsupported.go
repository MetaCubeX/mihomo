//go:build s390x

package dns

import (
	"context"
	"fmt"

	C "github.com/metacubex/mihomo/constant"

	D "github.com/miekg/dns"
)

// DNSCrypt relies on github.com/aead/chacha20, whose assembly does not compile on
// s390x. To keep the s390x build working, the sdns:// transport is stubbed out on
// that architecture: parsing still accepts the scheme, but resolving returns a
// clear error instead of pulling in the unbuildable dependency.
type dnsOverCrypt struct {
	addr string
}

// type check
var _ dnsClient = (*dnsOverCrypt)(nil)

func newDNSCryptClient(addr string, resolver *Resolver, params map[string]string, proxyAdapter C.ProxyAdapter, proxyName string) *dnsOverCrypt {
	return &dnsOverCrypt{addr: addr}
}

func (doc *dnsOverCrypt) Address() string { return doc.addr }

func (doc *dnsOverCrypt) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	return nil, fmt.Errorf("sdns:// DNSCrypt is not supported on this architecture (s390x)")
}

func (doc *dnsOverCrypt) ResetConnection() {}
