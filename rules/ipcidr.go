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
	if addr.IP == nil {
		return false
	}

	return i.ipnet.Contains(*addr.IP)
}

func (i *IPCIDR) Adapter() string {
	return i.adapter
}

func (i *IPCIDR) Payload() string {
	return i.ipnet.String()
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
