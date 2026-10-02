package config

import (
	"net/netip"

	"go4.org/netipx"
	"golang.org/x/exp/slices"
)

// Ebpf is the shared configuration contract for the Linux eBPF transparent
// inbound. Its fields are intentionally independent from a particular host
// implementation so the Clash Premium adapter can consume the same ABI.
type Ebpf struct {
	Enable            bool       `yaml:"enable" json:"enable"`
	LanInterface      []string   `yaml:"lan-interface" json:"lan-interface"`
	WanInterface      string     `yaml:"wan-interface" json:"wan-interface"`
	TProxyPort        uint16     `yaml:"tproxy-port" json:"tproxy-port"`
	AutoDirectOffload bool       `yaml:"auto-direct-offload" json:"auto-direct-offload"`
	RoutingMark       uint32     `yaml:"routing-mark" json:"routing-mark"`
	Lan               EbpfLan    `yaml:"lan" json:"lan"`
	Target            EbpfTarget `yaml:"target" json:"target"`
	Host              EbpfHost   `yaml:"host" json:"host"`
	BypassDSCPs       []uint8    `yaml:"bypass-dscps" json:"bypass-dscps"`
	BypassFWMarks     []uint32   `yaml:"bypass-fwmarks" json:"bypass-fwmarks"`
}

type EbpfLan struct {
	BypassSrcPorts []uint16       `yaml:"bypass-src-ports" json:"bypass-src-ports"`
	BypassSrcIPs   []netip.Prefix `yaml:"bypass-src-ips" json:"bypass-src-ips"`
	ProxySrcPorts  []uint16       `yaml:"proxy-src-ports" json:"proxy-src-ports"`
	ProxySrcIPs    []netip.Prefix `yaml:"proxy-src-ips" json:"proxy-src-ips"`
}

type EbpfTarget struct {
	BypassDstIPs   []netip.Prefix `yaml:"bypass-dst-ips" json:"bypass-dst-ips"`
	BypassDstPorts []uint16       `yaml:"bypass-dst-ports" json:"bypass-dst-ports"`
	ProxyDstIPs    []netip.Prefix `yaml:"proxy-dst-ips" json:"proxy-dst-ips"`
	ProxyDstPorts  []uint16       `yaml:"proxy-dst-ports" json:"proxy-dst-ports"`
	// DirectIPRuleProviders names explicitly selected ipcidr providers whose
	// prefixes are preloaded into the eBPF DIRECT LPM trie.
	DirectIPRuleProviders []string `yaml:"direct-ip-rule-providers" json:"direct-ip-rule-providers"`
}

type EbpfHost struct {
	ProxyLocal      bool     `yaml:"proxy-local" json:"proxy-local"`
	ProxyProcesses  []string `yaml:"proxy-processes" json:"proxy-processes"`
	BypassProcesses []string `yaml:"bypass-processes" json:"bypass-processes"`
}

// Sort canonicalizes unordered filters before comparing configurations during
// a hot reload. Callers must not change the meaning of a configuration by
// relying on input order.
func (e *Ebpf) Sort() {
	slices.Sort(e.LanInterface)
	slices.Sort(e.Lan.BypassSrcPorts)
	slices.SortFunc(e.Lan.BypassSrcIPs, netipx.ComparePrefix)
	slices.Sort(e.Lan.ProxySrcPorts)
	slices.SortFunc(e.Lan.ProxySrcIPs, netipx.ComparePrefix)
	slices.SortFunc(e.Target.BypassDstIPs, netipx.ComparePrefix)
	slices.Sort(e.Target.BypassDstPorts)
	slices.SortFunc(e.Target.ProxyDstIPs, netipx.ComparePrefix)
	slices.Sort(e.Target.ProxyDstPorts)
	slices.Sort(e.Target.DirectIPRuleProviders)
	slices.Sort(e.Host.ProxyProcesses)
	slices.Sort(e.Host.BypassProcesses)
	slices.Sort(e.BypassDSCPs)
	slices.Sort(e.BypassFWMarks)
}

// Equal compares canonicalized eBPF configurations. Sort both values before
// calling Equal when the values originate from independent YAML documents.
func (e *Ebpf) Equal(other Ebpf) bool {
	return e.Enable == other.Enable &&
		slices.Equal(e.LanInterface, other.LanInterface) &&
		e.WanInterface == other.WanInterface &&
		e.TProxyPort == other.TProxyPort &&
		e.AutoDirectOffload == other.AutoDirectOffload &&
		e.RoutingMark == other.RoutingMark &&
		slices.Equal(e.Lan.BypassSrcPorts, other.Lan.BypassSrcPorts) &&
		slices.Equal(e.Lan.BypassSrcIPs, other.Lan.BypassSrcIPs) &&
		slices.Equal(e.Lan.ProxySrcPorts, other.Lan.ProxySrcPorts) &&
		slices.Equal(e.Lan.ProxySrcIPs, other.Lan.ProxySrcIPs) &&
		slices.Equal(e.Target.BypassDstIPs, other.Target.BypassDstIPs) &&
		slices.Equal(e.Target.BypassDstPorts, other.Target.BypassDstPorts) &&
		slices.Equal(e.Target.ProxyDstIPs, other.Target.ProxyDstIPs) &&
		slices.Equal(e.Target.ProxyDstPorts, other.Target.ProxyDstPorts) &&
		slices.Equal(e.Target.DirectIPRuleProviders, other.Target.DirectIPRuleProviders) &&
		e.Host.ProxyLocal == other.Host.ProxyLocal &&
		slices.Equal(e.Host.ProxyProcesses, other.Host.ProxyProcesses) &&
		slices.Equal(e.Host.BypassProcesses, other.Host.BypassProcesses) &&
		slices.Equal(e.BypassDSCPs, other.BypassDSCPs) &&
		slices.Equal(e.BypassFWMarks, other.BypassFWMarks)
}
