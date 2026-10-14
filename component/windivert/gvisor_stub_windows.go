//go:build windows && !with_gvisor && (amd64 || 386)

package windivert

import tun "github.com/metacubex/sing-tun"

func (*Tun) startGVisor() error {
	return tun.ErrGVisorNotIncluded
}
