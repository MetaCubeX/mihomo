package inbound

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/mieru"
	"github.com/metacubex/mihomo/log"
	"google.golang.org/protobuf/proto"

	mieruserver "github.com/enfein/mieru/v3/apis/server"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
)

type Mieru struct {
	*Base
	option *MieruOption
	server mieruserver.Server
	mu     sync.Mutex
}

type MieruOption struct {
	BaseOption
	Transport string            `inbound:"transport"`
	Users     map[string]string `inbound:"users"`
}

type mieruListenerFactory struct{}

func (mieruListenerFactory) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return inbound.ListenContext(ctx, network, address)
}

func (mieruListenerFactory) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return inbound.ListenPacketContext(ctx, network, address)
}

func NewMieru(option *MieruOption) (*Mieru, error) {
	base, err := NewBase(&option.BaseOption)
	if err != nil {
		return nil, err
	}

	config, err := buildMieruServerConfig(option, base.ports)
	if err != nil {
		return nil, fmt.Errorf("failed to build mieru server config: %w", err)
	}
	s := mieruserver.NewServer()
	if err := s.Store(config); err != nil {
		return nil, fmt.Errorf("failed to store mieru server config: %w", err)
	}
	// Server is started lazily when Listen() is called for the first time.
	return &Mieru{
		Base:   base,
		option: option,
		server: s,
	}, nil
}

func (m *Mieru) Config() C.InboundConfig {
	return m.option
}

func (m *Mieru) Listen(tunnel C.Tunnel) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.server.IsRunning() {
		if err := m.server.Start(); err != nil {
			return fmt.Errorf("failed to start mieru server: %w", err)
		}
	}

	additions := m.config.Additions()
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-MIERU"),
			inbound.WithSpecialRules(""),
		}
	}

	go func() {
		for {
			c, req, err := m.server.Accept()
			if err != nil {
				if !m.server.IsRunning() {
					break
				} else {
					continue
				}
			}
			go mieru.Handle(c, tunnel, req, additions...)
		}
	}()
	log.Infoln("Mieru[%s] proxy listening at: %s", m.Name(), m.Address())
	return nil
}

func (m *Mieru) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.server.IsRunning() {
		return m.server.Stop()
	}

	return nil
}

var _ C.InboundListener = (*Mieru)(nil)

func (o MieruOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

func buildMieruServerConfig(option *MieruOption, ports utils.IntRanges[uint16]) (*mieruserver.ServerConfig, error) {
	if err := validateMieruOption(option); err != nil {
		return nil, fmt.Errorf("failed to validate mieru option: %w", err)
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("port is not set")
	}

	var transportProtocol *mierupb.TransportProtocol
	switch option.Transport {
	case "TCP":
		transportProtocol = mierupb.TransportProtocol_TCP.Enum()
	case "UDP":
		transportProtocol = mierupb.TransportProtocol_UDP.Enum()
	}
	var portBindings []*mierupb.PortBinding
	for _, portRange := range ports {
		if portRange.Start() == portRange.End() {
			portBindings = append(portBindings, &mierupb.PortBinding{
				Port:     proto.Int32(int32(portRange.Start())),
				Protocol: transportProtocol,
			})
		} else {
			portBindings = append(portBindings, &mierupb.PortBinding{
				PortRange: proto.String(fmt.Sprintf("%d-%d", portRange.Start(), portRange.End())),
				Protocol:  transportProtocol,
			})
		}
	}
	var users []*mierupb.User
	for username, password := range option.Users {
		users = append(users, &mierupb.User{
			Name:     proto.String(username),
			Password: proto.String(password),
		})
	}
	return &mieruserver.ServerConfig{
		Config: &mierupb.ServerConfig{
			PortBindings: portBindings,
			Users:        users,
		},
		StreamListenerFactory: mieruListenerFactory{},
		PacketListenerFactory: mieruListenerFactory{},
	}, nil
}

func validateMieruOption(option *MieruOption) error {
	if option.Transport != "TCP" && option.Transport != "UDP" {
		return fmt.Errorf("transport must be TCP or UDP")
	}
	if len(option.Users) == 0 {
		return fmt.Errorf("users is empty")
	}
	for username, password := range option.Users {
		if username == "" {
			return fmt.Errorf("username is empty")
		}
		if password == "" {
			return fmt.Errorf("password is empty")
		}
	}
	return nil
}
