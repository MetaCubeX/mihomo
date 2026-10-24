package inbound_test

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type udpEchoResult struct {
	metadata C.Metadata
	data     []byte
	address  net.Addr
	err      error
}

type udpEchoHandler struct {
	// Configure callbacks before starting the listener. A reply address need not
	// match the request, so later NAT tests can exercise alternate UDP sources.
	replyAddress func(*C.Metadata) net.Addr
	onResult     func(udpEchoResult)
	mu           sync.Mutex
	errs         []error
}

func (h *udpEchoHandler) Handle(packet C.UDPPacket, metadata *C.Metadata) {
	result := udpEchoResult{metadata: *metadata.Clone()}
	defer func() {
		packet.Drop()
		if h.onResult != nil {
			h.onResult(result)
		}
	}()

	address := M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort)
	if address.IsFqdn() {
		result.address = address
	} else {
		result.address = address.UDPAddr()
	}
	if h.replyAddress != nil {
		result.address = h.replyAddress(metadata)
	}
	data := packet.Data()
	if h.onResult != nil {
		// Listener buffers are returned to their pool by Drop, before observation.
		result.data = bytes.Clone(data)
	}
	_, result.err = packet.WriteBack(data, result.address)
	if result.err != nil {
		h.mu.Lock()
		h.errs = append(h.errs, result.err)
		h.mu.Unlock()
	}
}

func (tt *TestTunnel) checkUDPEcho(t *testing.T) {
	t.Helper()
	if tt.udpEcho == nil {
		return
	}
	tt.udpEcho.mu.Lock()
	defer tt.udpEcho.mu.Unlock()
	for _, err := range tt.udpEcho.errs {
		assert.NoError(t, err, "UDP echo WriteBack")
	}
}

// SOCKS UDP ASSOCIATE needs a shared TCP/UDP port. Other protocols bind each
// transport independently, so an unrelated TCP socket cannot block a UDP port.
type udpTestListenConfig struct {
	net.ListenConfig
	sharePort  bool
	tcpAddress string
	udpAddress string
	sharedTCP  net.Listener
	sharedUDP  net.PacketConn
}

// reserve binds both transports before the inbound asks for either one.
// Windows may refuse a UDP bind on a port that was free for TCP (for example
// an excluded port range), so retry with another port instead of failing.
func (c *udpTestListenConfig) reserve(ctx context.Context, address string) error {
	if c.sharedTCP != nil || c.sharedUDP != nil {
		return nil
	}
	var err error
	for i := 0; i < 10; i++ {
		var ln net.Listener
		ln, err = c.ListenConfig.Listen(ctx, "tcp", address)
		if err != nil {
			return err
		}
		var pc net.PacketConn
		pc, err = c.ListenConfig.ListenPacket(ctx, "udp", ln.Addr().String())
		if err == nil {
			c.sharedTCP, c.sharedUDP = ln, pc
			c.tcpAddress, c.udpAddress = ln.Addr().String(), pc.LocalAddr().String()
			return nil
		}
		_ = ln.Close()
	}
	return err
}

func (c *udpTestListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if c.sharePort {
		if err := c.reserve(ctx, address); err != nil {
			return nil, err
		}
		ln := c.sharedTCP
		c.sharedTCP = nil
		return ln, nil
	}
	ln, err := c.ListenConfig.Listen(ctx, network, address)
	if err == nil {
		c.tcpAddress = ln.Addr().String()
	}
	return ln, err
}

func (c *udpTestListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	if c.sharePort {
		if err := c.reserve(ctx, address); err != nil {
			return nil, err
		}
		pc := c.sharedUDP
		c.sharedUDP = nil
		return pc, nil
	}
	pc, err := c.ListenConfig.ListenPacket(ctx, network, address)
	if err == nil {
		c.udpAddress = pc.LocalAddr().String()
	}
	return pc, err
}

type udpTestPair struct {
	name         string
	sharePort    bool
	udpTransport bool
	local        bool
	ipReply      bool
	bound        bool
	peer         func(*testing.T, *udpEchoHandler) C.ProxyAdapter
	in           func(inbound.BaseOption) (C.InboundListener, error)
	out          func(netip.AddrPort, outbound.BasicOption) (C.ProxyAdapter, error)
}

var udpTestPairs = []udpTestPair{
	{
		name:      "SOCKS5",
		sharePort: true,
		in: func(base inbound.BaseOption) (C.InboundListener, error) {
			return inbound.NewSocks(&inbound.SocksOption{BaseOption: base, Users: inbound.AuthUsers{}, UDP: true})
		},
		out: newUDPSocksOutbound,
	},
	{
		name: "TrojanTLS",
		in: func(base inbound.BaseOption) (C.InboundListener, error) {
			return inbound.NewTrojan(&inbound.TrojanOption{
				BaseOption: base, Users: []inbound.TrojanUser{{Username: "test", Password: userUUID}},
				Certificate: tlsCertificate, PrivateKey: tlsPrivateKey,
			})
		},
		out: func(address netip.AddrPort, basic outbound.BasicOption) (C.ProxyAdapter, error) {
			return outbound.NewTrojan(outbound.TrojanOption{
				BasicOption: basic, Name: "udp_outbound", Server: address.Addr().String(), Port: int(address.Port()),
				Password: userUUID, Fingerprint: tlsFingerprint, UDP: true,
			})
		},
	},
}

func newUDPSocksOutbound(address netip.AddrPort, basic outbound.BasicOption) (C.ProxyAdapter, error) {
	return outbound.NewSocks5(outbound.Socks5Option{
		BasicOption: basic, Name: "udp_outbound", Server: address.Addr().String(), Port: int(address.Port()), UDP: true,
	})
}

func newUDPTestPair(t *testing.T, pair udpTestPair, replyAddress func(*C.Metadata) net.Addr) (C.ProxyAdapter, <-chan udpEchoResult) {
	t.Helper()
	tunnel := NewHttpTestTunnel()
	t.Cleanup(func() { assert.NoError(t, tunnel.Close()) })
	results := make(chan udpEchoResult, 1)
	tunnel.udpEcho.replyAddress = replyAddress
	tunnel.udpEcho.onResult = func(result udpEchoResult) { results <- result }

	if pair.peer != nil {
		return pair.peer(t, tunnel.udpEcho), results
	}
	lc := &udpTestListenConfig{sharePort: pair.sharePort}
	in, err := pair.in(inbound.BaseOption{
		NameStr: "udp_inbound", Listen: "127.0.0.1", Port: "0", ListenConfigForAPI: lc,
	})
	require.NoError(t, err)
	require.NoError(t, in.Listen(tunnel))
	t.Cleanup(func() { assert.NoError(t, in.Close()) })
	boundAddress := lc.tcpAddress
	if pair.udpTransport {
		boundAddress = lc.udpAddress
	}
	address, err := netip.ParseAddrPort(boundAddress)
	require.NoError(t, err)
	out, err := pair.out(address, outbound.BasicOption{DialerForAPI: tunnel.NewDialer(), TunnelForAPI: tunnel})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, out.Close()) })
	return out, results
}

func readUDPTestPacket(pc C.PacketConn, wait bool) ([]byte, net.Addr, error) {
	if wait {
		data, put, address, err := pc.WaitReadFrom()
		if put != nil {
			defer put()
		}
		return bytes.Clone(data), address, err
	}
	data := make([]byte, 65535)
	n, address, err := pc.ReadFrom(data)
	return data[:n], address, err
}
