//go:build no_gvisor

package fdbased

import (
	"os"
)

type FD struct {
	fd  int
	mtu uint32

	file *os.File
}
