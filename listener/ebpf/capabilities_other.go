//go:build !linux

package ebpf

import "errors"

var ErrUnsupported = errors.New("eBPF inbound requires Linux")

type Capabilities struct {
	BPF      bool
	TC       bool
	CgroupV2 bool
	SKLookup bool
}

func ProbeCapabilities() (Capabilities, error) {
	return Capabilities{}, ErrUnsupported
}
