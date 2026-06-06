//go:build !s390x

// DNSCrypt depends on github.com/aead/chacha20, whose assembly does not build on
// s390x. The sdns:// transport is therefore excluded on that architecture; see
// dnscrypt_unsupported.go for the stub used there.

package dns

import (
	"context"
	"fmt"
	"sync"

	C "github.com/metacubex/mihomo/constant"

	dnscrypt "github.com/ameshkov/dnscrypt/v2"
	"github.com/ameshkov/dnsstamps"
	D "github.com/miekg/dns"
)

// dnsOverCrypt is a DNSCrypt (sdns://) upstream. It wraps the AdGuard
// ameshkov/dnscrypt client: the DNSCrypt certificate is fetched once and the
// negotiated ResolverInfo is cached, then refreshed only when the resolver
// certificate expires (instead of being re-fetched on every query).
type dnsOverCrypt struct {
	addr  string // the original sdns:// stamp, also reported by Address()
	stamp dnsstamps.ServerStamp
	// parseErr is set when the stamp is malformed or does not encode a DNSCrypt
	// resolver. The dnsClient constructors return no error, so we stash it here
	// and surface it from ExchangeContext.
	parseErr error
	client   *dnscrypt.Client

	mu           sync.Mutex
	resolverInfo *dnscrypt.ResolverInfo
}

// type check
var _ dnsClient = (*dnsOverCrypt)(nil)

// newDNSCryptClient returns a DNSCrypt upstream for the given sdns:// stamp.
//
// v1 dials the resolver directly: the underlying library does its own socket
// dialing and does not accept an injected dialer, so the resolver / proxy
// parameters are accepted for signature parity with the other clients (and a
// future proxied follow-up) but are unused here.
func newDNSCryptClient(addr string, resolver *Resolver, params map[string]string, proxyAdapter C.ProxyAdapter, proxyName string) *dnsOverCrypt {
	doc := &dnsOverCrypt{
		addr: addr,
		client: &dnscrypt.Client{
			Net:     "udp",
			UDPSize: 4096,
			Timeout: DefaultTimeout,
		},
	}

	// Parse the stamp eagerly so misconfiguration fails fast with a clear message.
	stamp, err := dnsstamps.NewServerStampFromString(addr)
	switch {
	case err != nil:
		doc.parseErr = fmt.Errorf("invalid sdns:// stamp: %w", err)
	case stamp.Proto != dnsstamps.StampProtoTypeDNSCrypt:
		doc.parseErr = fmt.Errorf("unsupported sdns:// proto %q for DNSCrypt client, use the https:// or tls:// nameserver scheme instead", stamp.Proto.String())
	default:
		doc.stamp = stamp
	}

	return doc
}

// Address implements the dnsClient interface for *dnsOverCrypt.
func (doc *dnsOverCrypt) Address() string { return doc.addr }

func (doc *dnsOverCrypt) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	if doc.parseErr != nil {
		return nil, doc.parseErr
	}

	// ameshkov/dnscrypt's Exchange (and the cert fetch) doesn't respond to
	// context cancellation. Run it in a goroutine and select on ctx.Done() —
	// the same workaround used by the other dns clients (see dns/client.go).
	type result struct {
		msg *D.Msg
		err error
	}
	ch := make(chan result, 1)
	go func() {
		resolverInfo, err := doc.getResolverInfo()
		if err != nil {
			ch <- result{nil, err}
			return
		}
		msg, err := doc.client.Exchange(m, resolverInfo)
		ch <- result{msg, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ret := <-ch:
		return ret.msg, ret.err
	}
}

// getResolverInfo returns the cached ResolverInfo, (re)fetching the DNSCrypt
// certificate when there is no cached info or the cached certificate is no
// longer valid.
func (doc *dnsOverCrypt) getResolverInfo() (*dnscrypt.ResolverInfo, error) {
	doc.mu.Lock()
	defer doc.mu.Unlock()

	if doc.resolverInfo != nil && doc.resolverInfo.ResolverCert.VerifyDate() {
		return doc.resolverInfo, nil
	}

	resolverInfo, err := doc.client.DialStamp(doc.stamp)
	if err != nil {
		return nil, fmt.Errorf("fetching DNSCrypt cert for %s: %w", doc.addr, err)
	}
	doc.resolverInfo = resolverInfo

	return resolverInfo, nil
}

// ResetConnection drops the cached resolver info so the next query re-fetches
// the DNSCrypt certificate.
func (doc *dnsOverCrypt) ResetConnection() {
	doc.mu.Lock()
	defer doc.mu.Unlock()
	doc.resolverInfo = nil
}
