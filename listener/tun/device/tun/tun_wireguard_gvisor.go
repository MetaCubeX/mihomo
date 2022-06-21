//go:build !linux && !no_gvisor

package tun

import (
	"fmt"
	"github.com/Dreamacro/clash/listener/tun/device/iobased"
	"golang.zx2c4.com/wireguard/tun"
)

type TUN struct {
	*iobased.Endpoint
	nt     *tun.NativeTun
	mtu    uint32
	name   string
	offset int

	cache []byte
}

func closeIO(t *TUN) {
	if t.Endpoint != nil {
		t.Endpoint.Close()
	}
}

func newEq(t *TUN) error {
	ep, err := iobased.New(t, t.mtu, t.offset)
	if err != nil {
		return fmt.Errorf("create endpoint: %w", err)
	}
	t.Endpoint = ep
	return nil
}
