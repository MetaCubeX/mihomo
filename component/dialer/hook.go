package dialer

import (
	"errors"
	"net"
)

type DialerHookFunc = func(dialer *net.Dialer) error
type DialHookFunc = func(dialer *net.Dialer, network string, ip net.IP) error
type ListenPacketHookFunc = func(lc *net.ListenConfig, address string) (string, error)

var (
	DialerHook       DialerHookFunc
	DialHook         DialHookFunc
	ListenPacketHook ListenPacketHookFunc
)

var (
	ErrAddrNotFound      = errors.New("addr not found")
	ErrNetworkNotSupport = errors.New("network not support")
)

func ListenPacketWithInterface(name string) ListenPacketHookFunc {
	return func(lc *net.ListenConfig, address string) (string, error) {
		err := bindIfaceToListenConfig(lc, name)
		if err == errPlatformNotSupport {
			address, err = fallbackBindToListenConfig(name)
		}

		return address, err
	}
}

func DialerWithInterface(name string) DialHookFunc {
	return func(dialer *net.Dialer, network string, ip net.IP) error {
		err := bindIfaceToDialer(dialer, name)
		if err == errPlatformNotSupport {
			err = fallbackBindToDialer(dialer, network, ip, name)
		}

		return err
	}
}
