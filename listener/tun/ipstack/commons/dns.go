package commons

import (
	"net/netip"
	"time"

	"github.com/Dreamacro/clash/component/resolver"
	D "github.com/miekg/dns"
)

const DefaultDnsReadTimeout = time.Second * 10

func ShouldHijackDns(dnsAdds []netip.AddrPort, targetAddr netip.AddrPort) bool {
	for _, addrPort := range dnsAdds {
		if addrPort == targetAddr || (addrPort.Addr().IsUnspecified() && targetAddr.Port() == 53) {
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
		return nil, err
	}

	for _, ans := range r.Answer {
		header := ans.Header()

		if header.Class == D.ClassINET && (header.Rrtype == D.TypeA || header.Rrtype == D.TypeAAAA) {
			header.Ttl = 1
		}
	}

	r.SetRcode(msg, r.Rcode)
	r.Compress = true
	return r.Pack()
}
