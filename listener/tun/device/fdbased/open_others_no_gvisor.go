//go:build no_gvisor && !linux && !windows

package fdbased

import (
	"fmt"
)

func newEp(f *FD) error {
	return fmt.Errorf("unsupported gvisor on the build")
}
