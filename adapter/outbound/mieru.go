package outbound

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strconv"

	mieruclient "github.com/enfein/mieru/v3/apis/client"
	mierumodel "github.com/enfein/mieru/v3/apis/model"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
	"google.golang.org/protobuf/proto"
)

const (
	// Default MTU used in mieru UDP transport.
	mieruDefaultMTU = 1400
)

type Mieru struct {
	*Base
	option *MieruOption
	client mieruclient.Client
}

type MieruOption struct {
	BasicOption
	Name      string `proxy:"name"`
	Server    string `proxy:"server"`
	Port      int    `proxy:"port,omitempty"`
	PortRange string `proxy:"port-range,omitempty"`
	Transport string `proxy:"transport"`
	UserName  string `proxy:"username"`
	Password  string `proxy:"password"`
	MTU       int    `proxy:"mtu,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (m *Mieru) DialContext(ctx context.Context, metadata *C.Metadata, _ ...dialer.Option) (_ C.Conn, err error) {
	c, err := m.client.DialContext(ctx)
	if err != nil {
		return nil, err
	}

	addrSpec := mierumodel.AddrSpec{
		Port: int(metadata.DstPort),
	}
	if metadata.Host != "" {
		addrSpec.FQDN = metadata.Host
	} else {
		addrSpec.IP = metadata.DstIP.AsSlice()
	}
	if err := m.client.HandshakeWithConnect(ctx, c, addrSpec); err != nil {
		return nil, err
	}
	return NewConn(N.NewRefConn(c, m), m), nil
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
	if err := c.Start(); err != nil {
		return nil, fmt.Errorf("failed to start mieru client: %w", err)
	}

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
			udp:    false,
			xudp:   false,
			rmark:  option.RoutingMark,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
		option: &option,
		client: c,
	}
	runtime.SetFinalizer(outbound, closeMieru)
	return outbound, nil
}

func closeMieru(m *Mieru) {
	if m.client != nil {
		m.client.Stop()
	}
}

func buildMieruClientConfig(option MieruOption) (*mieruclient.ClientConfig, error) {
	if err := validateMieruOption(option); err != nil {
		return nil, fmt.Errorf("failed to validate mieru option: %w", err)
	}

	var transportProtocol *mierupb.TransportProtocol
	if option.Transport == "TCP" {
		transportProtocol = mierupb.TransportProtocol_TCP.Enum()
	} else if option.Transport == "UDP" {
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
	if option.MTU == 0 {
		option.MTU = mieruDefaultMTU
	}
	return &mieruclient.ClientConfig{
		Profile: &mierupb.ClientProfile{
			ProfileName: proto.String(option.Name),
			User: &mierupb.User{
				Name:     proto.String(option.UserName),
				Password: proto.String(option.Password),
			},
			Servers: []*mierupb.ServerEndpoint{server},
			Mtu:     proto.Int32(int32(option.MTU)),
			Multiplexing: &mierupb.MultiplexingConfig{
				// Multiplexing doesn't work well with connection tracking.
				Level: mierupb.MultiplexingLevel_MULTIPLEXING_OFF.Enum(),
			},
		},
	}, nil
}

func validateMieruOption(option MieruOption) error {
	if option.DialerProxy != "" {
		return fmt.Errorf("dialer proxy is not supported")
	}
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
	return nil
}

func beginAndEndPortFromPortRange(portRange string) (int, int, error) {
	var begin, end int
	_, err := fmt.Sscanf(portRange, "%d-%d", &begin, &end)
	return begin, end, err
}
