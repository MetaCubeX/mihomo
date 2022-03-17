package mars

import (
	"io"
	"net/netip"

	"github.com/Dreamacro/clash/listener/tun/ipstack/system/mars/nat"
)

type StackListener struct {
	device io.Closer
	tcp    *nat.TCP
	udp    *nat.UDP
}

func StartListener(device io.ReadWriteCloser, gateway netip.Addr, portal netip.Addr) (*StackListener, error) {
	tcp, udp, err := nat.Start(device, gateway, portal)
	if err != nil {
		return nil, err
	}

	return &StackListener{
		device: device,
		tcp:    tcp,
		udp:    udp,
	}, nil
}

func (t *StackListener) Close() error {
	_ = t.tcp.Close()
	_ = t.udp.Close()

	return t.device.Close()
}

func (t *StackListener) TCP() *nat.TCP {
	return t.tcp
}

func (t *StackListener) UDP() *nat.UDP {
	return t.udp
}
