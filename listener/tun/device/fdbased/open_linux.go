package fdbased

import (
	"github.com/Dreamacro/clash/listener/tun/device"
)

func open(fd int, mtu uint32) (device.Device, error) {
	f := &FD{fd: fd, mtu: mtu}

	return f, nil
}

func (f *FD) useEndpoint() error {
	return f.newLinuxEp()
}

func (f *FD) useIOBased() error {
	return nil
}

func (f *FD) Read(packet []byte) (int, error) {
	return f.read(packet)
}

func (f *FD) Write(packet []byte) (int, error) {
	return f.write(packet)
}
