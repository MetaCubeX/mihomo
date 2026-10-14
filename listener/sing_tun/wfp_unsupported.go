//go:build !windows || (!amd64 && !386)

package sing_tun

import "fmt"

func (*Listener) startWFP() error {
	return fmt.Errorf("wfp requires Windows amd64/386")
}
