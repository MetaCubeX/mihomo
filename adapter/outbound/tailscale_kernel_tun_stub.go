//go:build with_gvisor && !no_tailscale && !linux

package outbound

import (
	"errors"
	"net/netip"

	tstun "github.com/metacubex/tailscale-wireguard-go/tun"
)

type tailscaleKernelHostForwarder struct{}

func newTailscaleKernelHostForwarder(name string, option TailscaleHostForwardOption) (*tailscaleKernelHostForwarder, error) {
	return nil, errors.New("tailscale kernel host-forward mode is only supported on Linux")
}

func (k *tailscaleKernelHostForwarder) Device() tstun.Device {
	return nil
}

func (k *tailscaleKernelHostForwarder) Name() string {
	return ""
}

func (k *tailscaleKernelHostForwarder) MTU() uint32 {
	return 0
}

func (k *tailscaleKernelHostForwarder) Routes() []netip.Prefix {
	return nil
}

func (k *tailscaleKernelHostForwarder) Addresses() []netip.Prefix {
	return nil
}

func (k *tailscaleKernelHostForwarder) Configure(v4, v6 netip.Addr) error {
	return nil
}

func (k *tailscaleKernelHostForwarder) Close() error {
	return nil
}
