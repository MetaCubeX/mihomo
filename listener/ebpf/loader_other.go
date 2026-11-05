//go:build !linux

package ebpf

import cebpf "github.com/cilium/ebpf"

// Datapath has the same API on unsupported platforms so callers can always
// defer Close while platform validation reports a stable error.
type Datapath struct{}

func LoadDatapath() (*Datapath, error) {
	return nil, ErrUnsupported
}

func (d *Datapath) Map(string) *cebpf.Map { return nil }

func (d *Datapath) Program(string) *cebpf.Program { return nil }

func (d *Datapath) Close() error { return nil }
