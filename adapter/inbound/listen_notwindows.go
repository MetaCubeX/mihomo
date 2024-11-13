//go:build !windows

package inbound

import (
	"net"
	"os"
)

const SupportNamedPipe = false

func ListenNamedPipe(path string) (net.Listener, error) {
	return nil, os.ErrInvalid
}
