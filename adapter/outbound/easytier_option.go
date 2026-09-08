package outbound

import "github.com/metacubex/mihomo/component/easytier"

type EasyTierOption struct {
	BasicOption
	Name                string   `proxy:"name"`
	NetworkName         string   `proxy:"network-name,omitempty"`
	NetworkSecret       string   `proxy:"network-secret,omitempty"`
	Hostname            string   `proxy:"hostname,omitempty"`
	IPv4                string   `proxy:"ipv4,omitempty"`
	DHCP                bool     `proxy:"dhcp,omitempty"`
	Peers               []string `proxy:"peers,omitempty"`
	Listeners           []string `proxy:"listeners,omitempty"`
	NoListener          *bool    `proxy:"no-listener,omitempty"`
	MappedListeners     []string `proxy:"mapped-listeners,omitempty"`
	ExitNodes           []string `proxy:"exit-nodes,omitempty"`
	ProxyNetworks       []string `proxy:"proxy-networks,omitempty"`
	InstanceName        string   `proxy:"instance-name,omitempty"`
	StateDir            string   `proxy:"state-dir,omitempty"`
	Config              string   `proxy:"config,omitempty"`
	ConfigFile          string   `proxy:"config-file,omitempty"`
	UDP                 bool     `proxy:"udp,omitempty"`
	AcceptDNS           *bool    `proxy:"accept-dns,omitempty"`
	EnableExitNode      *bool    `proxy:"enable-exit-node,omitempty"`
	EnableEncryption    *bool    `proxy:"enable-encryption,omitempty"`
	EncryptionAlgorithm string   `proxy:"encryption-algorithm,omitempty"`
	PrivateMode         *bool    `proxy:"private-mode,omitempty"`
	LatencyFirst        *bool    `proxy:"latency-first,omitempty"`
	DisableP2P          *bool    `proxy:"disable-p2p,omitempty"`
	EnableKCPProxy      *bool    `proxy:"enable-kcp-proxy,omitempty"`
	DisableKCPInput     *bool    `proxy:"disable-kcp-input,omitempty"`
	EnableQUICProxy     *bool    `proxy:"enable-quic-proxy,omitempty"`
	DisableQUICInput    *bool    `proxy:"disable-quic-input,omitempty"`
	MTU                 int      `proxy:"mtu,omitempty"`
	TLDDNSZone          string   `proxy:"tld-dns-zone,omitempty"`
}

func (o EasyTierOption) structuredConfig() easytier.Config {
	instanceName := o.InstanceName
	if instanceName == "" {
		instanceName = o.Name
	}
	return easytier.Config{
		NetworkName:         o.NetworkName,
		NetworkSecret:       o.NetworkSecret,
		Hostname:            o.Hostname,
		IPv4:                o.IPv4,
		DHCP:                o.DHCP,
		Peers:               o.Peers,
		Listeners:           o.Listeners,
		NoListener:          o.NoListener,
		MappedListeners:     o.MappedListeners,
		ExitNodes:           o.ExitNodes,
		ProxyNetworks:       o.ProxyNetworks,
		InstanceName:        instanceName,
		AcceptDNS:           o.AcceptDNS,
		EnableExitNode:      o.EnableExitNode,
		EnableEncryption:    o.EnableEncryption,
		EncryptionAlgorithm: o.EncryptionAlgorithm,
		PrivateMode:         o.PrivateMode,
		LatencyFirst:        o.LatencyFirst,
		DisableP2P:          o.DisableP2P,
		EnableKCPProxy:      o.EnableKCPProxy,
		DisableKCPInput:     o.DisableKCPInput,
		EnableQUICProxy:     o.EnableQUICProxy,
		DisableQUICInput:    o.DisableQUICInput,
		MTU:                 o.MTU,
		TLDDNSZone:          o.TLDDNSZone,
	}
}
