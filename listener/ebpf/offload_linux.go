//go:build linux

package ebpf

import (
	"fmt"
	"net/netip"

	cebpf "github.com/cilium/ebpf"
)

// NewDatapathDestinationMap binds an Offloader to this datapath instance's
// IPv4 and IPv6 dynamic-bypass maps. Reapplying a diff is idempotent, so a
// partial kernel failure remains dirty and is corrected on the next retry.
func NewDatapathDestinationMap(datapath *Datapath) (DestinationMap, error) {
	if datapath == nil || datapath.collection == nil {
		return nil, fmt.Errorf("eBPF datapath is not loaded")
	}
	v4, v6 := datapath.Map("DYNAMIC_BYPASS_DST_IPS"), datapath.Map("DYNAMIC_BYPASS_DST_IP6S")
	if v4 == nil || v6 == nil {
		return nil, fmt.Errorf("eBPF datapath has no dynamic bypass maps")
	}
	return &datapathDestinationMap{v4: v4, v6: v6}, nil
}

type datapathDestinationMap struct{ v4, v6 *cebpf.Map }

func (m *datapathDestinationMap) Apply(add, remove []netip.Addr) error {
	for _, ip := range remove {
		if err := m.delete(ip); err != nil {
			return err
		}
	}
	for _, ip := range add {
		if err := m.update(ip); err != nil {
			return err
		}
	}
	return nil
}

func (m *datapathDestinationMap) update(ip netip.Addr) error {
	value := uint8(1)
	if ip.Is4() {
		return m.v4.Update(ip.As4(), value, cebpf.UpdateAny)
	}
	return m.v6.Update(ip.As16(), value, cebpf.UpdateAny)
}

func (m *datapathDestinationMap) delete(ip netip.Addr) error {
	if ip.Is4() {
		return m.v4.Delete(ip.As4())
	}
	return m.v6.Delete(ip.As16())
}
