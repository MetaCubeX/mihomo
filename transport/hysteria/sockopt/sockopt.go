package sockopt

import (
	"net"
	"syscall"
)

// https://github.com/v2fly/v2ray-core/blob/4e247840821f3dd326722d4db02ee3c237074fc2/transport/internet/config.pb.go#L420-L426

func BindDialer(d *net.Dialer, intf *net.Interface) {
	d.Control = func(network, address string, c syscall.RawConn) error {
		return bindRawConn(network, c, intf)
	}
}

func BindUDPConn(network string, conn *net.UDPConn, intf *net.Interface) error {
	c, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	return bindRawConn(network, c, intf)
}
