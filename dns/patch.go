package dns

import (
	"context"

	D "github.com/miekg/dns"
)

type LocalServer struct {
	handler handler
}

// ServeMsg implement resolver.LocalServer ResolveMsg
func (s *LocalServer) ServeMsg(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	return handlerWithContext(ctx, s.handler, msg)
}

func NewLocalServer(resolver *Resolver, mapper *ResolverEnhancer) *LocalServer {
	return &LocalServer{handler: NewHandler(resolver, mapper)}
}
