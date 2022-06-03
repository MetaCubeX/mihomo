//go:build !linux && no_gvisor

package tun

import (
	"golang.zx2c4.com/wireguard/tun"
)

type TUN struct {
	nt     *tun.NativeTun
	mtu    uint32
	name   string
	offset int

	cache []byte
}

func closeIO(t *TUN) {

}

func newEq(t *TUN) error {
	return nil
}
