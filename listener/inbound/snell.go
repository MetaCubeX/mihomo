package inbound

import (
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/snell"
	"github.com/metacubex/mihomo/log"
)

type SnellOption struct {
	BaseOption
	Psk      string          `inbound:"psk"`
	Version  int             `inbound:"version,omitempty"`
	UDP      bool            `inbound:"udp,omitempty"`
	ObfsOpts SnellObfsOption `inbound:"obfs-opts,omitempty"`
}

func (o SnellOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type SnellObfsOption struct {
	Mode string `obfs:"mode,omitempty"`
	Host string `obfs:"host,omitempty"`
}

type Snell struct {
	*Base
	config *SnellOption
	l      C.MultiAddrListener
	snell  LC.SnellServer
}

func NewSnell(options *SnellOption) (*Snell, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	if options.Version == 0 {
		options.Version = 4
	}
	if options.Version != 4 && options.Version != 5 {
		return nil, fmt.Errorf("snell inbound version %d is not supported", options.Version)
	}

	return &Snell{
		Base:   base,
		config: options,
		snell: LC.SnellServer{
			Listen:   base.RawAddress(),
			Psk:      options.Psk,
			Version:  options.Version,
			UDP:      options.UDP,
			ObfsMode: options.ObfsOpts.Mode,
			ObfsHost: options.ObfsOpts.Host,
		},
	}, nil
}

func (s *Snell) Config() C.InboundConfig {
	return s.config
}

func (s *Snell) Address() string {
	var addrList []string
	if s.l != nil {
		for _, addr := range s.l.AddrList() {
			addrList = append(addrList, addr.String())
		}
	}
	return strings.Join(addrList, ",")
}

func (s *Snell) Listen(tunnel C.Tunnel) error {
	var err error
	s.l, err = snell.New(s.snell, s.ListenConfig(), tunnel, s.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("Snell[%s] inbound listening at: %s", s.Name(), s.Address())
	return nil
}

func (s *Snell) Close() error {
	return s.l.Close()
}

var _ C.InboundListener = (*Snell)(nil)
