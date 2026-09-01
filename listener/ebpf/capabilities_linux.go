//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"os"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
)

// ErrUnsupported is returned where the operating system cannot host the eBPF
// inbound. Keep this wording stable: configuration validation exposes it to
// users and packages can use errors.Is to select an existing fallback.
var ErrUnsupported = errors.New("eBPF inbound requires Linux")

// Capabilities is the set of kernel features required by the shared v1
// datapath and its planned TC/sk_lookup attachments.
type Capabilities struct {
	BPF      bool
	TC       bool
	CgroupV2 bool
	SKLookup bool
}

// ProbeCapabilities performs only kernel feature probes. It never creates a
// persistent object, link, network namespace, route, or interface.
func ProbeCapabilities() (Capabilities, error) {
	caps := Capabilities{}
	if err := features.HaveMapType(cebpf.Array); err != nil {
		return caps, fmt.Errorf("eBPF BPF syscall unavailable: %w", err)
	}
	caps.BPF = true

	for _, mapType := range []cebpf.MapType{cebpf.LPMTrie, cebpf.LRUHash, cebpf.SockMap, cebpf.RingBuf} {
		if err := features.HaveMapType(mapType); err != nil {
			return caps, fmt.Errorf("eBPF map type %s unavailable: %w", mapType, err)
		}
	}
	if err := features.HaveProgramType(cebpf.SchedCLS); err != nil {
		return caps, fmt.Errorf("eBPF TC classifier unavailable: %w", err)
	}
	if err := features.HaveProgramHelper(cebpf.SchedCLS, asm.FnRedirect); err != nil {
		return caps, fmt.Errorf("eBPF TC redirect helper unavailable: %w", err)
	}
	caps.TC = true

	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		return caps, fmt.Errorf("eBPF inbound requires cgroup v2: %w", err)
	}
	caps.CgroupV2 = true

	if err := features.HaveProgramType(cebpf.SkLookup); err != nil {
		return caps, fmt.Errorf("eBPF sk_lookup unavailable: %w", err)
	}
	if err := features.HaveProgramHelper(cebpf.SkLookup, asm.FnSkAssign); err != nil {
		return caps, fmt.Errorf("eBPF sk_lookup assignment helper unavailable: %w", err)
	}
	caps.SKLookup = true

	return caps, nil
}
