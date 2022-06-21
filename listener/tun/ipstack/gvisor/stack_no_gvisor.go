//go:build no_gvisor

package gvisor

import (
	"fmt"
	"github.com/Dreamacro/clash/adapter/inbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/tun/device"
	"github.com/Dreamacro/clash/listener/tun/ipstack"
	"github.com/Dreamacro/clash/log"
	"net/netip"
)

// New allocates a new *gvStack with given options.
func New(device device.Device, dnsHijack []netip.AddrPort, tunAddress netip.Prefix, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) (ipstack.Stack, error) {
	log.Fatalln("unsupported gvisor stack on the build")
	return nil, fmt.Errorf("unsupported gvisor stack on the build")
}
