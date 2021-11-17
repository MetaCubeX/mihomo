package dns

import D "github.com/miekg/dns"

type LocalServer struct {
	handler handler
}

// ServeMsg implement resolver.LocalServer ResolveMsg
func (s *LocalServer) ServeMsg(msg *D.Msg) (*D.Msg, error) {
	return handlerWithContext(s.handler, msg)
}

func NewLocalServer(resolver *Resolver, mapper *ResolverEnhancer) *LocalServer {
	return &LocalServer{handler: NewHandler(resolver, mapper)}
}
