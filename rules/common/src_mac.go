package common

import (
	"fmt"
	"net"

	"github.com/metacubex/mihomo/component/neighbor"
	C "github.com/metacubex/mihomo/constant"
)

type SrcMAC struct {
	Base
	mac     string
	adapter string
}

func NewSrcMAC(payload, adapter string) (*SrcMAC, error) {
	if !neighbor.Supported {
		return nil, neighbor.ErrUnsupported
	}
	mac, err := net.ParseMAC(payload)
	if err != nil || len(mac) != 6 {
		return nil, fmt.Errorf("invalid source MAC address: %q (expected a 48-bit MAC)", payload)
	}
	return &SrcMAC{mac: mac.String(), adapter: adapter}, nil
}

func (r *SrcMAC) RuleType() C.RuleType { return C.SrcMAC }
func (r *SrcMAC) Adapter() string      { return r.adapter }
func (r *SrcMAC) Payload() string      { return r.mac }
func (r *SrcMAC) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if helper.FindSourceMAC != nil {
		helper.FindSourceMAC()
	}
	return metadata.SrcMAC != "" && metadata.SrcMAC == r.mac, r.adapter
}

var _ C.Rule = (*SrcMAC)(nil)
