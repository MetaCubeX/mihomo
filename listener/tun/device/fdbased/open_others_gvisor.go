//go:build !no_gvisor && !linux && !windows

package fdbased

import (
	"fmt"
	"os"

	"github.com/Dreamacro/clash/listener/tun/device/iobased"
)

func (f *FD) newEpOther() error {
	ep, err := iobased.New(os.NewFile(uintptr(f.fd), f.Name()), f.mtu, 0)
	if err != nil {
		return fmt.Errorf("create endpoint: %w", err)
	}
	f.LinkEndpoint = ep
	return nil
}
