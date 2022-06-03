//go:build !no_gvisor

package fdbased

import (
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"os"
)

type FD struct {
	stack.LinkEndpoint

	fd  int
	mtu uint32

	file *os.File
}
