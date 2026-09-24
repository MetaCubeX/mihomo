package config

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEbpfSortAndEqual(t *testing.T) {
	left := Ebpf{
		LanInterface: []string{"eth1", "br-lan"},
		Lan: EbpfLan{
			BypassSrcPorts: []uint16{5353, 22},
			BypassSrcIPs: []netip.Prefix{
				netip.MustParsePrefix("192.168.2.0/24"),
				netip.MustParsePrefix("192.168.1.0/24"),
			},
		},
		Target: EbpfTarget{
			ProxyDstPorts: []uint16{443, 80},
		},
		Host:          EbpfHost{ProxyProcesses: []string{"mihomo", "dnsmasq"}},
		BypassDSCPs:   []uint8{46, 0},
		BypassFWMarks: []uint32{2, 1},
	}
	right := Ebpf{
		LanInterface: []string{"br-lan", "eth1"},
		Lan: EbpfLan{
			BypassSrcPorts: []uint16{22, 5353},
			BypassSrcIPs: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.0/24"),
				netip.MustParsePrefix("192.168.2.0/24"),
			},
		},
		Target: EbpfTarget{
			ProxyDstPorts: []uint16{80, 443},
		},
		Host:          EbpfHost{ProxyProcesses: []string{"dnsmasq", "mihomo"}},
		BypassDSCPs:   []uint8{0, 46},
		BypassFWMarks: []uint32{1, 2},
	}

	require.False(t, left.Equal(right))
	left.Sort()
	right.Sort()
	require.True(t, left.Equal(right))
}
