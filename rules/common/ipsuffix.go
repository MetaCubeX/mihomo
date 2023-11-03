package common

import (
	C "github.com/metacubex/mihomo/constant"
	"net/netip"
)

type IPSuffix struct {
	*Base
	ipBytes     []byte
	bits        int
	payload     string
	adapter     string
	isSourceIP  bool
	noResolveIP bool
}

func (is *IPSuffix) RuleType() C.RuleType {
	if is.isSourceIP {
		return C.SrcIPSuffix
	}
	return C.IPSuffix
}

func (is *IPSuffix) Match(metadata *C.Metadata) (bool, string) {
	ip := metadata.DstIP
	if is.isSourceIP {
		ip = metadata.SrcIP
	}

	mIPBytes := ip.AsSlice()
	if len(is.ipBytes) != len(mIPBytes) {
		return false, ""
	}

	size := len(mIPBytes)
	bits := is.bits

	for i := bits / 8; i > 0; i-- {
		if is.ipBytes[size-i] != mIPBytes[size-i] {
			return false, ""
		}
	}

	if (is.ipBytes[size-bits/8-1] << (8 - bits%8)) != (mIPBytes[size-bits/8-1] << (8 - bits%8)) {
		return false, ""
	}

	return true, is.adapter
}

func (is *IPSuffix) Adapter() string {
	return is.adapter
}

func (is *IPSuffix) Payload() string {
	return is.payload
}

func (is *IPSuffix) ShouldResolveIP() bool {
	return !is.noResolveIP
}

func NewIPSuffix(payload, adapter string, isSrc, noResolveIP bool) (*IPSuffix, error) {
	ipnet, err := netip.ParsePrefix(payload)
	if err != nil {
		return nil, errPayload
	}

	return &IPSuffix{
		Base:        &Base{},
		payload:     payload,
		ipBytes:     ipnet.Addr().AsSlice(),
		bits:        ipnet.Bits(),
		adapter:     adapter,
		isSourceIP:  isSrc,
		noResolveIP: noResolveIP,
	}, nil
}
