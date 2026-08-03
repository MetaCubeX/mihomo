package inbound

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

type Base struct {
	config       *BaseOption
	name         string
	specialRules string
	listenAddr   netip.Addr
	ports        utils.IntRanges[uint16]
	unixSocket   string
}

func NewBase(options *BaseOption) (*Base, error) {
	return newBase(options, false)
}

func newBase(options *BaseOption, allowUnixSocket bool) (*Base, error) {
	if filepath.IsAbs(options.Port) {
		if !allowUnixSocket {
			return nil, fmt.Errorf("unix socket is not supported by this listener type")
		}
		if options.Listen != "" {
			return nil, fmt.Errorf("listen cannot be used with a unix socket")
		}
		if options.RoutingMark != 0 {
			return nil, fmt.Errorf("routing-mark cannot be used with a unix socket")
		}
		path := filepath.Clean(options.Port)
		if path == string(filepath.Separator) || strings.Contains(path, ",") {
			return nil, fmt.Errorf("invalid unix socket path: %s", options.Port)
		}
		options.Port = path
		return &Base{
			name:         options.Name(),
			specialRules: options.SpecialRules,
			unixSocket:   path,
			config:       options,
		}, nil
	}
	if options.Listen == "" {
		options.Listen = "0.0.0.0"
	}
	addr, err := netip.ParseAddr(options.Listen)
	if err != nil {
		return nil, err
	}
	ports, err := utils.NewUnsignedRanges[uint16](options.Port)
	if err != nil {
		return nil, err
	}
	return &Base{
		name:         options.Name(),
		listenAddr:   addr,
		specialRules: options.SpecialRules,
		ports:        ports,
		config:       options,
	}, nil
}

// Config implements constant.InboundListener
func (b *Base) Config() C.InboundConfig {
	return b.config
}

// Address implements constant.InboundListener
func (b *Base) Address() string {
	return b.RawAddress()
}

// Close implements constant.InboundListener
func (*Base) Close() error {
	return nil
}

// Name implements constant.InboundListener
func (b *Base) Name() string {
	return b.name
}

// RawAddress implements constant.InboundListener
func (b *Base) RawAddress() string {
	if b.unixSocket != "" {
		return b.unixSocket
	}
	if len(b.ports) == 0 {
		return net.JoinHostPort(b.listenAddr.String(), "0")
	}
	address := make([]string, 0, len(b.ports))
	b.ports.Range(func(port uint16) bool {
		address = append(address, net.JoinHostPort(b.listenAddr.String(), strconv.Itoa(int(port))))
		return true
	})
	return strings.Join(address, ",")
}

// Listen implements constant.InboundListener
func (*Base) Listen(tunnel C.Tunnel) error {
	return nil
}

func (b *Base) Additions() []inbound.Addition {
	return b.config.Additions()
}

func (b *Base) ListenConfig() C.InboundListenConfig {
	lc := b.config.ListenConfig()
	if b.unixSocket != "" {
		return unixSocketListenConfig{InboundListenConfig: lc, path: b.unixSocket}
	}
	return lc
}

type unixSocketListenConfig struct {
	C.InboundListenConfig
	path string
}

func (c unixSocketListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if network != "tcp" || address != c.path {
		return nil, fmt.Errorf("invalid unix socket listen request: %s %s", network, address)
	}
	return c.InboundListenConfig.Listen(ctx, "unix", address)
}

func (c unixSocketListenConfig) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	return nil, fmt.Errorf("unix socket listener is stream-only")
}

var _ C.InboundListener = (*Base)(nil)

type BaseOption struct {
	NameStr      string `inbound:"name"`
	Listen       string `inbound:"listen,omitempty"`
	Port         string `inbound:"port,omitempty"`
	SpecialRules string `inbound:"rule,omitempty"`
	SpecialProxy string `inbound:"proxy,omitempty"`
	RoutingMark  int    `inbound:"routing-mark,omitempty"`

	//
	// The following parameters are used internally, assign value by the structure decoder are disallowed
	//
	ListenConfigForAPI C.InboundListenConfig `inbound:"-"`
}

func (o BaseOption) Name() string {
	return o.NameStr
}

func (o BaseOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

func (o BaseOption) Additions() []inbound.Addition {
	return []inbound.Addition{
		inbound.WithInName(o.NameStr),
		inbound.WithSpecialRules(o.SpecialRules),
		inbound.WithSpecialProxy(o.SpecialProxy),
	}
}

func (o BaseOption) ListenConfig() C.InboundListenConfig {
	if o.ListenConfigForAPI != nil {
		return o.ListenConfigForAPI
	}
	lc := inbound.NewListenConfig()
	lc.SetRouteMark(o.RoutingMark)
	return lc
}

var _ C.InboundConfig = (*BaseOption)(nil)

func optionToString(option any) string {
	str, _ := json.Marshal(option)
	return string(str)
}
