package dns

import (
	"context"
	"errors"

	"github.com/metacubex/mihomo/component/resolver"
	icontext "github.com/metacubex/mihomo/context"
	D "github.com/miekg/dns"
)

type Service struct {
	handler handler
}

// ServeMsg implement [resolver.Service] ResolveMsg
func (s *Service) ServeMsg(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	if len(msg.Question) == 0 {
		return nil, errors.New("at least one question is required")
	}

	r, err := s.handler(icontext.NewDNSContext(ctx), msg)
	if err != nil {
		return r, err
	}

	// echo back EDNS0: if the client asked with an OPT, reply with our own OPT.
	// OPT is a per-hop pseudo-record (RFC 6891), so we generate it here instead of
	// caching/forwarding the upstream one. Doing it at this convergence point covers
	// both the listening DNS server (ServeDNS) and the TUN hijack relay path.
	// 1232 is the fragmentation-safe UDP payload size recommended by
	// https://dnsflagday.net/2020/ : the IPv6 minimum MTU (1280) minus
	// the IPv6 and UDP header sizes (40 + 8).
	if reqOpt := msg.IsEdns0(); reqOpt != nil && r != nil && r.IsEdns0() == nil {
		r.SetEdns0(1232, reqOpt.Do())
	}

	return r, nil
}

var _ resolver.Service = (*Service)(nil)

func NewService(resolver resolver.Resolver, mapper *ResolverEnhancer) *Service {
	return &Service{handler: newHandler(resolver, mapper)}
}
