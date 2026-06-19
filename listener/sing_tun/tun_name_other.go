//go:build !(darwin || linux || freebsd)

package sing_tun

import "os"

func getTunnelName(fd int32) (string, error) {
	return "", os.ErrInvalid
}
