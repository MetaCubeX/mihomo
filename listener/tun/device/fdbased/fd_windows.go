package fdbased

import (
	"errors"

	"github.com/Dreamacro/clash/listener/tun/device"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type FD struct {
	stack.LinkEndpoint
}

func Open(_ string, _ uint32) (device.Device, error) {
	return nil, errors.New("not supported")
}

func (f *FD) Name() string {
	return ""
}

func (f *FD) Type() string {
	return Driver
}

func (f *FD) Read(_ []byte) (int, error) {
	return 0, nil
}

func (f *FD) Write(_ []byte) (int, error) {
	return 0, nil
}

func (f *FD) Close() error {
	return nil
}

func (f *FD) UseEndpoint() error {
	return nil
}

func (f *FD) UseIOBased() error {
	return nil
}

func (f *FD) MTU() uint32 {
	return 0
}

var _ device.Device = (*FD)(nil)
