//go:build !no_gvisor

package device

import (
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Device is the interface that implemented by network layer devices (e.g. tun),
// and easy to use as stack.LinkEndpoint.
type Device interface {
	stack.LinkEndpoint

	// Name returns the current name of the device.
	Name() string

	// Type returns the driver type of the device.
	Type() string

	// Read packets from tun device
	Read(packet []byte) (int, error)

	// Write packets to tun device
	Write(packet []byte) (int, error)

	// Close stops and closes the device.
	Close() error

	// UseEndpoint work for gVisor stack
	UseEndpoint() error

	// UseIOBased work for other ip stack
	UseIOBased() error
}
