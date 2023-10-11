package inbound

import (
	"net"

	C "github.com/Dreamacro/clash/constant"
)

type Addition func(metadata *C.Metadata)

func (a Addition) Apply(metadata *C.Metadata) {
	a(metadata)
}

func WithInName(name string) Addition {
	return func(metadata *C.Metadata) {
		metadata.InName = name
	}
}

func WithInUser(user string) Addition {
	return func(metadata *C.Metadata) {
		metadata.InUser = user
	}
}

func WithSpecialRules(specialRules string) Addition {
	return func(metadata *C.Metadata) {
		metadata.SpecialRules = specialRules
	}
}

func WithSpecialProxy(specialProxy string) Addition {
	return func(metadata *C.Metadata) {
		metadata.SpecialProxy = specialProxy
	}
}

func WithSrcAddr(addr net.Addr) Addition {
	return func(metadata *C.Metadata) {
		addrPort := parseAddr(addr)
		metadata.SrcIP = addrPort.Addr().Unmap()
		metadata.SrcPort = addrPort.Port()
	}
}

func WithDstAddr(addr net.Addr) Addition {
	return func(metadata *C.Metadata) {
		addrPort := parseAddr(addr)
		metadata.DstIP = addrPort.Addr().Unmap()
		metadata.DstPort = addrPort.Port()
	}
}

func WithInAddr(addr net.Addr) Addition {
	return func(metadata *C.Metadata) {
		addrPort := parseAddr(addr)
		metadata.InIP = addrPort.Addr().Unmap()
		metadata.InPort = addrPort.Port()
	}
}
