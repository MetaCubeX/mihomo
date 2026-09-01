package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEbpfDefaults(t *testing.T) {
	raw := DefaultRawConfig().Ebpf
	ebpf, err := parseEbpf(raw)
	require.NoError(t, err)
	require.False(t, ebpf.Enable)
	require.Equal(t, "auto", ebpf.WanInterface)
	require.EqualValues(t, 12345, ebpf.TProxyPort)
	require.True(t, ebpf.AutoDirectOffload)
	require.EqualValues(t, 0x1dae, ebpf.RoutingMark)
	require.EqualValues(t, []uint16{22, 67, 68, 5353}, ebpf.Lan.BypassSrcPorts)
	require.Len(t, ebpf.Target.BypassDstIPs, 6)
}

func TestEbpfFullYAML(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte(`
ebpf:
  enable: true
  lan-interface: [eth1, br-lan]
  wan-interface: pppoe-wan
  tproxy-port: 23456
  auto-direct-offload: false
  routing-mark: 0x1234
  lan:
    bypass-src-ports: [5353, 22]
    bypass-src-ips: [192.168.2.0/24, 192.168.1.0/24]
    proxy-src-ports: [8443, 443]
    proxy-src-ips: [10.1.0.0/16]
  target:
    bypass-dst-ips: [fe80::/10, 10.0.0.0/8]
    bypass-dst-ports: [53]
    proxy-dst-ips: [2001:db8::/32]
    proxy-dst-ports: [443, 80]
  host:
    proxy-local: true
    proxy-processes: [mihomo, dnsmasq]
    bypass-processes: [sshd]
  bypass-dscps: [46, 0]
  bypass-fwmarks: [2, 1]
`))
	require.NoError(t, err)

	general, err := parseGeneral(raw)
	require.NoError(t, err)
	ebpf := general.Ebpf
	require.True(t, ebpf.Enable)
	require.Equal(t, []string{"br-lan", "eth1"}, ebpf.LanInterface)
	require.Equal(t, "pppoe-wan", ebpf.WanInterface)
	require.EqualValues(t, 23456, ebpf.TProxyPort)
	require.False(t, ebpf.AutoDirectOffload)
	require.EqualValues(t, 0x1234, ebpf.RoutingMark)
	require.EqualValues(t, []uint16{22, 5353}, ebpf.Lan.BypassSrcPorts)
	require.Equal(t, "192.168.1.0/24", ebpf.Lan.BypassSrcIPs[0].String())
	require.Equal(t, "10.0.0.0/8", ebpf.Target.BypassDstIPs[0].String())
	require.True(t, ebpf.Host.ProxyLocal)
	require.Equal(t, []string{"dnsmasq", "mihomo"}, ebpf.Host.ProxyProcesses)
	require.EqualValues(t, []uint8{0, 46}, ebpf.BypassDSCPs)
	require.EqualValues(t, []uint32{1, 2}, ebpf.BypassFWMarks)
}

func TestEbpfValidation(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		errContains string
	}{
		{
			name: "invalid CIDR",
			yaml: `ebpf:
  target:
    bypass-dst-ips: [not-a-cidr]`,
			errContains: "ebpf.target.bypass-dst-ips[0] is not a valid CIDR",
		},
		{
			name: "invalid tproxy port",
			yaml: `ebpf:
  tproxy-port: 0`,
			errContains: "ebpf.tproxy-port must be in 1..65535",
		},
		{
			name: "invalid filter port",
			yaml: `ebpf:
  lan:
    proxy-src-ports: [65536]`,
			errContains: "ebpf.lan.proxy-src-ports[0] must be in 1..65535",
		},
		{
			name: "invalid DSCP",
			yaml: `ebpf:
  bypass-dscps: [64]`,
			errContains: "ebpf.bypass-dscps[0] must be in 0..63",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := UnmarshalRawConfig([]byte(tt.yaml))
			require.NoError(t, err)
			_, err = parseGeneral(raw)
			require.ErrorContains(t, err, tt.errContains)
		})
	}
}

func TestEbpfConflicts(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		errContains string
	}{
		{
			name: "tun",
			yaml: `ebpf:
  enable: true
tun:
  enable: true`,
			errContains: "ebpf.enable and tun.enable cannot both be enabled",
		},
		{
			name: "iptables",
			yaml: `ebpf:
  enable: true
iptables:
  enable: true`,
			errContains: "ebpf.enable and iptables.enable cannot both be enabled",
		},
		{
			name: "disabled",
			yaml: `ebpf:
  enable: false
tun:
  enable: true
iptables:
  enable: true`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := UnmarshalRawConfig([]byte(tt.yaml))
			require.NoError(t, err)
			_, err = parseGeneral(raw)
			if tt.errContains == "" {
				require.NoError(t, validateInboundConflicts(raw))
				return
			}
			require.NoError(t, err)
			require.ErrorContains(t, validateInboundConflicts(raw), tt.errContains)
		})
	}
}
