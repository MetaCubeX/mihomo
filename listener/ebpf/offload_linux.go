//go:build linux

package ebpf

import (
	"fmt"
	"net/netip"

	cebpf "github.com/cilium/ebpf"
)

// NewDatapathDestinationMap binds an Offloader to this datapath instance's
// IPv4 and IPv6 dynamic policy maps. Reapplying a diff is idempotent, so a
// partial kernel failure remains dirty and is corrected on the next retry.
func NewDatapathDestinationMap(datapath *Datapath) (DestinationMap, error) {
	if datapath == nil || datapath.collection == nil {
		return nil, fmt.Errorf("eBPF datapath is not loaded")
	}
	direct4, direct6 := datapath.Map("DYN_DIRECT4"), datapath.Map("DYN_DIRECT6")
	proxy4, proxy6 := datapath.Map("DYN_PROXY4"), datapath.Map("DYN_PROXY6")
	if direct4 == nil || direct6 == nil || proxy4 == nil || proxy6 == nil {
		return nil, fmt.Errorf("eBPF datapath has no dynamic policy maps")
	}
	return &datapathDestinationMap{direct4: direct4, direct6: direct6, proxy4: proxy4, proxy6: proxy6}, nil
}

type datapathDestinationMap struct{ direct4, direct6, proxy4, proxy6 *cebpf.Map }

func (m *datapathDestinationMap) Apply(diff DestinationSets) error {
	// Install vetoes first and remove direct entries before removing a veto so a
	// shared IP cannot transiently be released to the fast path.
	for _, ip := range diff.ProxyAdd {
		if err := m.update(m.proxy4, m.proxy6, ip); err != nil {
			return err
		}
	}
	for _, ip := range diff.DirectRemove {
		if err := m.delete(m.direct4, m.direct6, ip); err != nil {
			return err
		}
	}
	for _, ip := range diff.DirectAdd {
		if err := m.update(m.direct4, m.direct6, ip); err != nil {
			return err
		}
	}
	for _, ip := range diff.ProxyRemove {
		if err := m.delete(m.proxy4, m.proxy6, ip); err != nil {
			return err
		}
	}
	return nil
}

func (m *datapathDestinationMap) update(v4, v6 *cebpf.Map, ip netip.Addr) error {
	value := uint8(1)
	if ip.Is4() {
		return v4.Update(ip.As4(), value, cebpf.UpdateAny)
	}
	return v6.Update(ip.As16(), value, cebpf.UpdateAny)
}

func (m *datapathDestinationMap) delete(v4, v6 *cebpf.Map, ip netip.Addr) error {
	if ip.Is4() {
		return v4.Delete(ip.As4())
	}
	return v6.Delete(ip.As16())
}
