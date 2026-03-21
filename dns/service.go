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

	return s.handler(icontext.NewDNSContext(ctx), msg)
}

var _ resolver.Service = (*Service)(nil)

func NewService(resolver *Resolver, mapper *ResolverEnhancer) *Service {
	return &Service{handler: newHandler(resolver, mapper)}
}
