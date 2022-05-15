package commons

import (
	"net/netip"
	"time"

	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"

	D "github.com/miekg/dns"
)

const DefaultDnsReadTimeout = time.Second * 10

func ShouldHijackDns(dnsHijack []C.DNSUrl, targetAddr netip.AddrPort, network string) bool {
	for _, dns := range dnsHijack {
		if dns.Network == network && (dns.AddrPort.AddrPort == targetAddr || (dns.AddrPort.Addr().IsUnspecified() && dns.AddrPort.Port() == targetAddr.Port())) {
			return true
		}
	}
	return false
}

func RelayDnsPacket(payload []byte) ([]byte, error) {
	msg := &D.Msg{}
	if err := msg.Unpack(payload); err != nil {
		return nil, err
	}

	r, err := resolver.ServeMsg(msg)
	if err != nil {
		m := new(D.Msg)
		m.SetRcode(msg, D.RcodeServerFailure)
		return m.Pack()
	}

	r.SetRcode(msg, r.Rcode)
	r.Compress = true
	return r.Pack()
}
