//go:build !no_gvisor && (linux || android)

package fdbased

import (
	"fmt"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
)

func (f *FD) newLinuxEp() error {
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

func (f *FD) read(packet []byte) (int, error) {
	n, gvErr := rawfile.BlockingRead(f.fd, packet)
	if gvErr != nil {
		return 0, fmt.Errorf("read error: %s", gvErr.String())
	}

	return n, nil
}

func (f *FD) write(packet []byte) (int, error) {
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
