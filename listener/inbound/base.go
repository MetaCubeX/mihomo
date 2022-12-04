package inbound

import (
	"net"
	"net/netip"
	"strconv"

	C "github.com/Dreamacro/clash/constant"
)

type Base struct {
	name            string
	preferRulesName string
	listenAddr      netip.Addr
	port            int
}

func NewBase(options *BaseOption) (*Base, error) {
	if options.Listen == "" {
		options.Listen = "0.0.0.0"
	}
	addr, err := netip.ParseAddr(options.Listen)
	if err != nil {
		return nil, err
	}
	return &Base{
		name:            options.Name,
		listenAddr:      addr,
		preferRulesName: options.PreferRulesName,
		port:            options.Port,
	}, nil
}

// Address implements constant.NewListener
func (b *Base) Address() string {
	return b.RawAddress()
}

// Close implements constant.NewListener
func (*Base) Close() error {
	return nil
}

// Name implements constant.NewListener
func (b *Base) Name() string {
	return b.name
}

// RawAddress implements constant.NewListener
func (b *Base) RawAddress() string {
	return net.JoinHostPort(b.listenAddr.String(), strconv.Itoa(int(b.port)))
}

// ReCreate implements constant.NewListener
func (*Base) ReCreate(tcpIn chan<- C.ConnContext, udpIn chan<- C.PacketAdapter) error {
	return nil
}

type BaseOption struct {
	Name            string `inbound:"name"`
	Listen          string `inbound:"listen,omitempty"`
	Port            int    `inbound:"port"`
	PreferRulesName string `inbound:"rule,omitempty"`
}

var _ C.NewListener = (*Base)(nil)
