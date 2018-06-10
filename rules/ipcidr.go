package rules

import (
	"net"

	C "github.com/Dreamacro/clash/constant"
)

type IPCIDR struct {
	ipnet   *net.IPNet
	adapter string
}

func (i *IPCIDR) RuleType() C.RuleType {
	return C.IPCIDR
}

func (i *IPCIDR) IsMatch(addr *C.Addr) bool {
	if addr.AddrType == C.AtypDomainName {
		return false
	}
	ip := net.ParseIP(addr.Host)
	if ip == nil {
		return false
	}

	return i.ipnet.Contains(ip)
}

func (g *IPCIDR) Adapter() string {
	return g.adapter
}

func NewIPCIDR(s string, adapter string) *IPCIDR {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
	}
	return &IPCIDR{
		ipnet:   ipnet,
		adapter: adapter,
	}
}
