package fdbased

import (
	"fmt"

	"github.com/Dreamacro/clash/listener/tun/device"

	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
)

func open(fd int, mtu uint32) (device.Device, error) {
	f := &FD{fd: fd, mtu: mtu}

	return f, nil
}

func (f *FD) useEndpoint() error {
	ep, err := fdbased.New(&fdbased.Options{
		FDs: []int{f.fd},
		MTU: f.mtu,
		// TUN only, ignore ethernet header.
		EthernetHeader: false,
	})
	if err != nil {
		return fmt.Errorf("create endpoint: %w", err)
	}
	f.LinkEndpoint = ep
	return nil
}

func (f *FD) useIOBased() error {
	return nil
}

func (f *FD) Read(packet []byte) (int, error) {
	n, gvErr := rawfile.BlockingRead(f.fd, packet)
	if gvErr != nil {
		return 0, fmt.Errorf("read error: %s", gvErr.String())
	}

	return n, nil
}

func (f *FD) Write(packet []byte) (int, error) {
	n := len(packet)
	if n == 0 {
		return 0, nil
	}

	gvErr := rawfile.NonBlockingWrite(f.fd, packet)
	if gvErr != nil {
		return 0, fmt.Errorf("write error: %s", gvErr.String())
	}
	return n, nil
}
