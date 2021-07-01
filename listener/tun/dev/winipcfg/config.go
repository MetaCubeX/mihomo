// +build windows

package winipcfg

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type IPCidr struct {
	IP   net.IP
	Cidr uint8
}

func (r *IPCidr) String() string {
	return fmt.Sprintf("%s/%d", r.IP.String(), r.Cidr)
}

func (r *IPCidr) Bits() uint8 {
	if r.IP.To4() != nil {
		return 32
	}
	return 128
}

func (r *IPCidr) IPNet() net.IPNet {
	return net.IPNet{
		IP:   r.IP,
		Mask: net.CIDRMask(int(r.Cidr), int(r.Bits())),
	}
}

func (r *IPCidr) MaskSelf() {
	bits := int(r.Bits())
	mask := net.CIDRMask(int(r.Cidr), bits)
	for i := 0; i < bits/8; i++ {
		r.IP[i] &= mask[i]
	}
}

func ParseIPCidr(ipcidr string) *IPCidr {
	s := strings.Split(ipcidr, "/")
	if len(s) != 2 {
		return nil
	}
	cidr, err := strconv.Atoi(s[1])
	if err != nil {
		return nil
	}
	return &IPCidr{
		IP:   net.ParseIP(s[0]),
		Cidr: uint8(cidr),
	}
}
