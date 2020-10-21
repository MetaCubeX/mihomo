// +build !linux,!darwin

package dialer

import "net"

func bindIfaceToDialer(dialer *net.Dialer, ifaceName string) error {
	return errNotSupport
}

func bindIfaceToListenConfig(lc *net.ListenConfig, ifaceName string) error {
	return errNotSupport
}
