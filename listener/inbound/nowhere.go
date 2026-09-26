package inbound

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/transport/nowhere"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/network"
	"github.com/metacubex/tls"
)

type NowhereOption struct {
	BaseOption
	Password    string   `inbound:"password"`
	Network     []string `inbound:"network,omitempty"`
	TCPPort     int      `inbound:"tcp-port,omitempty"`
	UDPPort     int      `inbound:"udp-port,omitempty"`
	Morph       bool     `inbound:"morph,omitempty"`
	Certificate string   `inbound:"certificate"`
	PrivateKey  string   `inbound:"private-key"`
}

func (o NowhereOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Nowhere struct {
	*Base
	config    *NowhereOption
	server    *nowhere.Server
	addresses []string
	listenTCP bool
	listenUDP bool
}

func NewNowhere(options *NowhereOption) (*Nowhere, error) {
	if options.TCPPort < 0 || options.TCPPort > 65535 || options.UDPPort < 0 || options.UDPPort > 65535 {
		return nil, errors.New("nowhere: invalid carrier port")
	}
	networks := options.Network
	if len(networks) == 0 {
		networks = []string{"tcp", "udp"}
	}
	var listenTCP, listenUDP bool
	for _, network := range networks {
		switch strings.ToLower(network) {
		case "tcp":
			listenTCP = true
		case "udp":
			listenUDP = true
		default:
			return nil, errors.New("nowhere: network must contain only tcp or udp")
		}
	}
	if len(options.Password) < 1 || len(options.Password) > 255 {
		return nil, errors.New("nowhere: password must contain 1..255 bytes")
	}
	if options.Certificate == "" || options.PrivateKey == "" {
		return nil, errors.New("nowhere: certificate and private-key are required")
	}
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	if (options.TCPPort != 0 || options.UDPPort != 0) && strings.Contains(base.RawAddress(), ",") {
		return nil, errors.New("nowhere: carrier ports cannot be combined with a port range")
	}
	return &Nowhere{Base: base, config: options, listenTCP: listenTCP, listenUDP: listenUDP}, nil
}

func (n *Nowhere) Config() C.InboundConfig {
	return n.config
}

func (n *Nowhere) Address() string {
	return strings.Join(n.addresses, ",")
}

func (n *Nowhere) Close() error {
	if n.server != nil {
		return n.server.Close()
	}
	return nil
}

func (n *Nowhere) Listen(tunnel C.Tunnel) error {
	loader, err := ca.NewTLSKeyPairLoader(n.config.Certificate, n.config.PrivateKey)
	if err != nil {
		return err
	}
	h, err := sing.NewListenerHandler(sing.ListenerConfig{Tunnel: tunnel, Type: C.NOWHERE, Additions: n.Additions()})
	if err != nil {
		return err
	}
	s, err := nowhere.NewServer(nowhere.ServerConfig{
		Password: n.config.Password,
		Morph:    n.config.Morph,
		TLSConfig: &tls.Config{
			Time:           ntp.Now,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return loader() },
		},
		Handler: &nowhereHandler{handler: h},
	})
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	lc := n.ListenConfig()
	var addresses []string
	for _, addr := range strings.Split(n.RawAddress(), ",") {
		host, _, _ := net.SplitHostPort(addr)
		if n.listenTCP {
			tcpAddr := addr
			if n.config.TCPPort != 0 {
				tcpAddr = net.JoinHostPort(host, strconv.Itoa(n.config.TCPPort))
			}
			l, err := lc.Listen(context.Background(), "tcp", tcpAddr)
			if err != nil {
				return err
			}
			// Share an ephemeral base port, but do not let tcp-port override
			// the UDP listener's independently configured base port.
			if n.config.TCPPort == 0 {
				addr = l.Addr().String()
			}
			if err = s.ServeTCP(l); err != nil {
				l.Close()
				return err
			}
			addresses = append(addresses, l.Addr().String())
		}
		if n.listenUDP {
			if n.config.UDPPort != 0 {
				addr = net.JoinHostPort(host, strconv.Itoa(n.config.UDPPort))
			}
			pc, err := lc.ListenPacket(context.Background(), "udp", addr)
			if err != nil {
				return err
			}
			addr = pc.LocalAddr().String()
			if err = s.ServeUDP(pc); err != nil {
				pc.Close()
				return err
			}
			if len(addresses) == 0 || addresses[len(addresses)-1] != addr {
				addresses = append(addresses, addr)
			}
		}
	}
	n.server = s
	n.addresses = addresses
	ok = true
	log.Infoln("Nowhere[%s] proxy listening at: %s", n.Name(), n.Address())
	return nil
}

type nowhereHandler struct {
	handler *sing.ListenerHandler
}

func (h *nowhereHandler) HandleTCP(ctx context.Context, conn *nowhere.ServerConn, target string) {
	// Like AnyTLS, acknowledge the inbound before entering the tunnel, which
	// may sniff application data and has no outbound setup-result callback.
	// Later dial failures close the connection rather than return DIAL_FAILED.
	if err := conn.HandshakeSuccess(); err != nil {
		return
	}
	ctx = sing.WithAdditions(ctx, func(m *C.Metadata) { m.NowhereHops = nowhere.Hops(ctx) })
	if err := h.handler.NewConnection(ctx, conn, M.Metadata{
		Source:      M.SocksaddrFromNet(conn.RemoteAddr()),
		Destination: M.ParseSocksaddr(target),
	}); err != nil {
		h.handler.NewError(ctx, err)
	}
}

func (h *nowhereHandler) HandleUDP(ctx context.Context, conn *nowhere.ServerPacketConn, target string, source net.Addr) {
	// UDP uses the same packet-driven NAT path as the other sing inbounds.
	if err := conn.HandshakeSuccess(); err != nil {
		return
	}
	ctx = sing.WithAdditions(ctx, func(m *C.Metadata) { m.NowhereHops = nowhere.Hops(ctx) })
	if err := h.handler.NewPacketConnection(ctx, &nowherePacketConn{NetPacketConn: bufio.NewPacketConn(conn)}, M.Metadata{
		Source:      M.SocksaddrFromNet(source),
		Destination: M.ParseSocksaddr(target),
	}); err != nil {
		h.handler.NewError(ctx, err)
	}
}

// Use sing's read-wait interface to preserve full-sized Nowhere datagrams;
// the shared handler's default packet buffer is smaller than the wire limit.
type nowherePacketConn struct {
	network.NetPacketConn
	readWaitOptions network.ReadWaitOptions
}

func (c *nowherePacketConn) InitializeReadWaiter(options network.ReadWaitOptions) bool {
	options.MTU = 65535
	c.readWaitOptions = options
	return false
}

func (c *nowherePacketConn) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	_ = c.SetReadDeadline(time.Now().Add(sing.UDPTimeout))
	buffer := c.readWaitOptions.NewPacketBuffer()
	destination, err := c.ReadPacket(buffer)
	if err != nil {
		buffer.Release()
		return nil, M.Socksaddr{}, err
	}
	c.readWaitOptions.PostReturn(buffer)
	return buffer, destination, nil
}

var _ network.PacketReadWaiter = (*nowherePacketConn)(nil)
var _ C.InboundListener = (*Nowhere)(nil)
