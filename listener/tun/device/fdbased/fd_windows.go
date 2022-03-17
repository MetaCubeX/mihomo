package fdbased

import (
	"errors"

	"github.com/Dreamacro/clash/listener/tun/device"
)

func Open(name string, mtu uint32) (device.Device, error) {
	return nil, errors.New("not supported")
}
