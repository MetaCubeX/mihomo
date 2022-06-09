//go:build !no_gvisor

package fdbased

import (
	"os"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type FD struct {
	stack.LinkEndpoint

	fd  int
	mtu uint32

	file *os.File
}
