package inbound

import (
	"net"

	C "github.com/metacubex/mihomo/constant"
)

type Addition func(metadata *C.Metadata)

func ApplyAdditions(metadata *C.Metadata, additions ...Addition) {
	for _, addition := range additions {
		addition(metadata)
	}
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

func WithDstAddr(addr net.Addr) Addition {
	return func(metadata *C.Metadata) {
		_ = metadata.SetRemoteAddr(addr)
	}
}

func WithSrcAddr(addr net.Addr) Addition {
	return func(metadata *C.Metadata) {
		m := C.Metadata{}
		if err := m.SetRemoteAddr(addr); err == nil {
			metadata.SrcIP = m.DstIP
			metadata.SrcPort = m.DstPort
		}
	}
}

func WithInAddr(addr net.Addr) Addition {
	return func(metadata *C.Metadata) {
		m := C.Metadata{}
		if err := m.SetRemoteAddr(addr); err == nil {
			metadata.InIP = m.DstIP
			metadata.InPort = m.DstPort
		}
	}
}

func WithDSCP(dscp uint8) Addition {
	return func(metadata *C.Metadata) {
		metadata.DSCP = dscp
	}
}

func Placeholder(metadata *C.Metadata) {}
