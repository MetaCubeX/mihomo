//go:build no_gvisor

package fdbased

import (
	"fmt"
)

func (f *FD) newLinuxEp() error {
	return fmt.Errorf("unsupported gvisor on the build")
}

func (f *FD) read(packet []byte) (int, error) {
	return 0, fmt.Errorf("unsupported gvisor on the build")
}

func (f *FD) write(packet []byte) (int, error) {
	return 0, fmt.Errorf("unsupported gvisor on the build")
}
