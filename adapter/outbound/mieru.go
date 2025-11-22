package outbound

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"

	CN "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"

	mieruclient "github.com/enfein/mieru/v3/apis/client"
	mierucommon "github.com/enfein/mieru/v3/apis/common"
	mierumodel "github.com/enfein/mieru/v3/apis/model"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"
)

type Mieru struct {
	*Base
	option *MieruOption
	client mieruclient.Client
	mu     sync.Mutex
}

type MieruOption struct {
	BasicOption
	Name          string `proxy:"name"`
	Server        string `proxy:"server"`
	Port          int    `proxy:"port,omitempty"`
	PortRange     string `proxy:"port-range,omitempty"`
	Transport     string `proxy:"transport"`
	UDP           bool   `proxy:"udp,omitempty"`
	UserName      string `proxy:"username"`
	Password      string `proxy:"password"`
	Multiplexing  string `proxy:"multiplexing,omitempty"`
	HandshakeMode string `proxy:"handshake-mode,omitempty"`
}

type mieruPacketDialer struct {
	C.Dialer
}

var _ mierucommon.PacketDialer = (*mieruPacketDialer)(nil)

func (pd mieruPacketDialer) ListenPacket(ctx context.Context, network, laddr, raddr string) (net.PacketConn, error) {
	rAddrPort, err := netip.ParseAddrPort(raddr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %s: %w", raddr, err)
	}
	return pd.Dialer.ListenPacket(ctx, network, laddr, rAddrPort)
}

// DialContext implements C.ProxyAdapter
func (m *Mieru) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if err := m.ensureClientIsRunning(); err != nil {
		return nil, err
	}
	addr := metadataToMieruNetAddrSpec(metadata)
	c, err := m.client.DialContext(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("dial to %s failed: %w", addr, err)
	}
	return NewConn(c, m), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (m *Mieru) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = m.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	if err := m.ensureClientIsRunning(); err != nil {
		return nil, err
	}
	c, err := m.client.DialContext(ctx, metadata.UDPAddr())
	if err != nil {
		return nil, fmt.Errorf("dial to %s failed: %w", metadata.UDPAddr(), err)
	}
	return newPacketConn(CN.NewThreadSafePacketConn(mierucommon.NewUDPAssociateWrapper(mierucommon.NewPacketOverStreamTunnel(c))), m), nil
}

// SupportUOT implements C.ProxyAdapter
func (m *Mieru) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (m *Mieru) ProxyInfo() C.ProxyInfo {
	info := m.Base.ProxyInfo()
	info.DialerProxy = m.option.DialerProxy
	return info
}

func (m *Mieru) ensureClientIsRunning() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.client.IsRunning() {
		return nil
	}

	// Create a dialer and add it to the client config, before starting the client.
	var dialer C.Dialer = dialer.NewDialer(m.DialOptions()...)
	var err error
	if len(m.option.DialerProxy) > 0 {
		dialer, err = proxydialer.NewByName(m.option.DialerProxy, dialer)
		if err != nil {
			return err
		}
	}
	config, err := m.client.Load()
	if err != nil {
		return err
	}
	config.Dialer = dialer
	config.PacketDialer = mieruPacketDialer{Dialer: dialer}
	if err := m.client.Store(config); err != nil {
		return err
	}

	if err := m.client.Start(); err != nil {
		return fmt.Errorf("failed to start mieru client: %w", err)
	}
	return nil
}

func NewMieru(option MieruOption) (*Mieru, error) {
	config, err := buildMieruClientConfig(option)
	if err != nil {
		return nil, fmt.Errorf("failed to build mieru client config: %w", err)
	}
	c := mieruclient.NewClient()
	if err := c.Store(config); err != nil {
		return nil, fmt.Errorf("failed to store mieru client config: %w", err)
	}
	// Client is started lazily on the first use.

	var addr string
	if option.Port != 0 {
		addr = net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	} else {
		beginPort, _, _ := beginAndEndPortFromPortRange(option.PortRange)
		addr = net.JoinHostPort(option.Server, strconv.Itoa(beginPort))
	}
	outbound := &Mieru{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			iface:  option.Interface,
			tp:     C.Mieru,
			udp:    option.UDP,
			xudp:   false,
			rmark:  option.RoutingMark,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
		option: &option,
		client: c,
	}
	return outbound, nil
}

// Close implements C.ProxyAdapter
func (m *Mieru) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client != nil && m.client.IsRunning() {
		return m.client.Stop()
	}
	return nil
}

func metadataToMieruNetAddrSpec(metadata *C.Metadata) mierumodel.NetAddrSpec {
	spec := mierumodel.NetAddrSpec{
		Net: metadata.NetWork.String(),
	}
	if metadata.Host != "" {
		spec.AddrSpec = mierumodel.AddrSpec{
			FQDN: metadata.Host,
			Port: int(metadata.DstPort),
		}
	} else {
		spec.AddrSpec = mierumodel.AddrSpec{
			IP:   metadata.DstIP.AsSlice(),
			Port: int(metadata.DstPort),
		}
	}
	return spec
}

func buildMieruClientConfig(option MieruOption) (*mieruclient.ClientConfig, error) {
	if err := validateMieruOption(option); err != nil {
		return nil, fmt.Errorf("failed to validate mieru option: %w", err)
	}

	var transportProtocol = mierupb.TransportProtocol_UNKNOWN_TRANSPORT_PROTOCOL.Enum()
	switch option.Transport {
	case "TCP":
		transportProtocol = mierupb.TransportProtocol_TCP.Enum()
	case "UDP":
		transportProtocol = mierupb.TransportProtocol_UDP.Enum()
	}
	var server *mierupb.ServerEndpoint
	if net.ParseIP(option.Server) != nil {
		// server is an IP address
		if option.PortRange != "" {
			server = &mierupb.ServerEndpoint{
				IpAddress: proto.String(option.Server),
				PortBindings: []*mierupb.PortBinding{
					{
						PortRange: proto.String(option.PortRange),
						Protocol:  transportProtocol,
					},
				},
			}
		} else {
			server = &mierupb.ServerEndpoint{
				IpAddress: proto.String(option.Server),
				PortBindings: []*mierupb.PortBinding{
					{
						Port:     proto.Int32(int32(option.Port)),
						Protocol: transportProtocol,
					},
				},
			}
		}
	} else {
		// server is a domain name
		if option.PortRange != "" {
			server = &mierupb.ServerEndpoint{
				DomainName: proto.String(option.Server),
				PortBindings: []*mierupb.PortBinding{
					{
						PortRange: proto.String(option.PortRange),
						Protocol:  transportProtocol,
					},
				},
			}
		} else {
			server = &mierupb.ServerEndpoint{
				DomainName: proto.String(option.Server),
				PortBindings: []*mierupb.PortBinding{
					{
						Port:     proto.Int32(int32(option.Port)),
						Protocol: transportProtocol,
					},
				},
			}
		}
	}
	config := &mieruclient.ClientConfig{
		Profile: &mierupb.ClientProfile{
			ProfileName: proto.String(option.Name),
			User: &mierupb.User{
				Name:     proto.String(option.UserName),
				Password: proto.String(option.Password),
			},
			Servers: []*mierupb.ServerEndpoint{server},
		},
	}
	if multiplexing, ok := mierupb.MultiplexingLevel_value[option.Multiplexing]; ok {
		config.Profile.Multiplexing = &mierupb.MultiplexingConfig{
			Level: mierupb.MultiplexingLevel(multiplexing).Enum(),
		}
	}
	if handshakeMode, ok := mierupb.HandshakeMode_value[option.HandshakeMode]; ok {
		config.Profile.HandshakeMode = (*mierupb.HandshakeMode)(&handshakeMode)
	}
	return config, nil
}

func validateMieruOption(option MieruOption) error {
	if option.Name == "" {
		return fmt.Errorf("name is empty")
	}
	if option.Server == "" {
		return fmt.Errorf("server is empty")
	}
	if option.Port == 0 && option.PortRange == "" {
		return fmt.Errorf("either port or port-range must be set")
	}
	if option.Port != 0 && option.PortRange != "" {
		return fmt.Errorf("port and port-range cannot be set at the same time")
	}
	if option.Port != 0 && (option.Port < 1 || option.Port > 65535) {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	if option.PortRange != "" {
		begin, end, err := beginAndEndPortFromPortRange(option.PortRange)
		if err != nil {
			return fmt.Errorf("invalid port-range format")
		}
		if begin < 1 || begin > 65535 {
			return fmt.Errorf("begin port must be between 1 and 65535")
		}
		if end < 1 || end > 65535 {
			return fmt.Errorf("end port must be between 1 and 65535")
		}
		if begin > end {
			return fmt.Errorf("begin port must be less than or equal to end port")
		}
	}

	if option.Transport != "TCP" && option.Transport != "UDP" {
		return fmt.Errorf("transport must be TCP or UDP")
	}
	if option.UserName == "" {
		return fmt.Errorf("username is empty")
	}
	if option.Password == "" {
		return fmt.Errorf("password is empty")
	}
	if option.Multiplexing != "" {
		if _, ok := mierupb.MultiplexingLevel_value[option.Multiplexing]; !ok {
			return fmt.Errorf("invalid multiplexing level: %s", option.Multiplexing)
		}
	}
	if option.HandshakeMode != "" {
		if _, ok := mierupb.HandshakeMode_value[option.HandshakeMode]; !ok {
			return fmt.Errorf("invalid handshake mode: %s", option.HandshakeMode)
		}
	}
	return nil
}

func beginAndEndPortFromPortRange(portRange string) (int, int, error) {
	var begin, end int
	_, err := fmt.Sscanf(portRange, "%d-%d", &begin, &end)
	return begin, end, err
}
