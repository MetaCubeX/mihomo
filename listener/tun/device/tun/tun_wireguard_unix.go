//go:build !linux && !windows

package tun

import "golang.zx2c4.com/wireguard/tun"

const (
	offset     = 4 /* 4 bytes TUN_PI */
	defaultMTU = 1500
)

func newDevice(name string, mtu int) (tun.Device, error) {
	return tun.CreateTUN(name, mtu)
}
