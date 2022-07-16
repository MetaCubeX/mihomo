//go:build !linux && !windows

package fdbased

import (
	"fmt"
	"os"

	"github.com/Dreamacro/clash/listener/tun/device"
)

func open(fd int, mtu uint32) (device.Device, error) {
	f := &FD{fd: fd, mtu: mtu}

	return f, nil
}

func (f *FD) useEndpoint() error {
	return f.newEpOther()
}

func (f *FD) useIOBased() error {
	f.file = os.NewFile(uintptr(f.fd), f.Name())
	if f.file == nil {
		return fmt.Errorf("create IOBased failed, can not open file: %s", f.Name())
	}
	return nil
}

func (f *FD) Read(packet []byte) (int, error) {
	return f.file.Read(packet)
}

func (f *FD) Write(packet []byte) (int, error) {
	return f.file.Write(packet)
}
