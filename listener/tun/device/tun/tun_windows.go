package tun

import (
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

func init() {
	guid, _ := windows.GUIDFromString("{330EAEF8-7578-5DF2-D97B-8DADC0EA85CB}")

	tun.WintunTunnelType = "Meta"
	tun.WintunStaticRequestedGUID = &guid
}

func (t *TUN) LUID() uint64 {
	return t.nt.LUID()
}
