//go:build linux

package ebpf

import (
	"fmt"
	"sync"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Datapath owns the BPF programs and maps created for one eBPF inbound
// instance. Loading it does not attach a program or change routing; that is
// deliberately left to the network-namespace lifecycle stage.
type Datapath struct {
	collection *cebpf.Collection
	closeOnce  sync.Once
}

// LoadDatapath creates the generated maps and programs after verifying that
// the running kernel provides the facilities used by the next data-path
// stages. It does not attach anything to an interface or cgroup.
func LoadDatapath() (*Datapath, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("prepare eBPF memlock limit: %w", err)
	}
	if _, err := ProbeCapabilities(); err != nil {
		return nil, err
	}

	spec, err := loadDatapath()
	if err != nil {
		return nil, fmt.Errorf("read eBPF datapath specification: %w", err)
	}

	collection, err := cebpf.NewCollectionWithOptions(spec, cebpf.CollectionOptions{
		Programs: cebpf.ProgramOptions{LogLevel: cebpf.LogLevelBranch, LogSize: 2 * 1024 * 1024},
	})
	if err != nil {
		// cilium/ebpf identifies the rejected program and includes the kernel
		// verifier log in this error when it is available.
		return nil, fmt.Errorf("load eBPF collection (including verifier log): %w", err)
	}

	return &Datapath{collection: collection}, nil
}

// Map returns an owned datapath map by its stable ABI name, or nil when the
// requested map is not part of this version of the datapath.
func (d *Datapath) Map(name string) *cebpf.Map {
	if d == nil || d.collection == nil {
		return nil
	}
	return d.collection.Maps[name]
}

// Program returns an owned datapath program by its stable ABI name, or nil
// when the requested program is not part of this version of the datapath.
func (d *Datapath) Program(name string) *cebpf.Program {
	if d == nil || d.collection == nil {
		return nil
	}
	return d.collection.Programs[name]
}

// Close releases all BPF object file descriptors. It is safe to call more
// than once, including on a nil or partially constructed datapath.
func (d *Datapath) Close() error {
	if d == nil {
		return nil
	}
	d.closeOnce.Do(func() {
		if d.collection != nil {
			d.collection.Close()
			d.collection = nil
		}
	})
	return nil
}
