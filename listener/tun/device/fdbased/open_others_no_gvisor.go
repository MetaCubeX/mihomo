//go:build no_gvisor && !linux && !windows

package fdbased

import (
	"fmt"
)

func (f *FD) newEpOther() error {
	return fmt.Errorf("unsupported gvisor on the build")
}
