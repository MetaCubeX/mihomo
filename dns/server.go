package dns

import (
	stdContext "context"
	"errors"
	"net"

	"github.com/metacubex/mihomo/common/sockopt"
	"github.com/metacubex/mihomo/context"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
)

var (
	address   string
	tcpServer = &Server{}
	udpServer = &Server{}

	dnsDefaultTTL uint32 = 600
)

type Server struct {
	*D.Server
	handler handler
}

// ServeDNS implement D.Handler ServeDNS
func (s *Server) ServeDNS(w D.ResponseWriter, r *D.Msg) {
	msg, err := handlerWithContext(stdContext.Background(), s.handler, r)
	if err != nil {
		D.HandleFailed(w, r)
		return
	}
	msg.Compress = true
	w.WriteMsg(msg)
}

func handlerWithContext(stdCtx stdContext.Context, handler handler, msg *D.Msg) (*D.Msg, error) {
	if len(msg.Question) == 0 {
		return nil, errors.New("at least one question is required")
	}

	ctx := context.NewDNSContext(stdCtx, msg)
	return handler(ctx, msg)
}

func (s *Server) SetHandler(handler handler) {
	s.handler = handler
}

func ReCreateServer(addr string, resolver *Resolver, mapper *ResolverEnhancer) {
	if addr == address && resolver != nil {
		handler := NewHandler(resolver, mapper)
		tcpServer.SetHandler(handler)
		udpServer.SetHandler(handler)
		return
	}

	if tcpServer.Server != nil {
		tcpServer.Shutdown()
		tcpServer = &Server{}
		address = ""
	}

	if udpServer.Server != nil {
		udpServer.Shutdown()
		udpServer = &Server{}
		address = ""
	}

	if addr == "" {
		return
	}

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start DNS server error: %s", err.Error())
		}
	}()

	_, port, err := net.SplitHostPort(addr)
	if port == "0" || port == "" || err != nil {
		return
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return
	}

	l, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return
	}

	p, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return
	}

	err = sockopt.UDPReuseaddr(p)
	if err != nil {
		log.Warnln("Failed to Reuse UDP Address: %s", err)

		err = nil
	}

	address = addr
	handler := NewHandler(resolver, mapper)

	tcpServer = &Server{handler: handler}
	tcpServer.Server = &D.Server{Addr: addr, Listener: l, Handler: tcpServer}

	udpServer = &Server{handler: handler}
	udpServer.Server = &D.Server{Addr: addr, PacketConn: p, Handler: udpServer}

	go func() {
		tcpServer.ActivateAndServe()
	}()

	go func() {
		udpServer.ActivateAndServe()
	}()

	log.Infoln("DNS server listening at: %s", p.LocalAddr().String())
}
