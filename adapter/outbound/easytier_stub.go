//go:build no_easytier

package outbound

import "fmt"

type EasyTier struct {
	*Base
}

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
	SecureMode          *bool    `proxy:"secure-mode,omitempty"`
	LocalPrivateKey     string   `proxy:"local-private-key,omitempty"`
	LocalPublicKey      string   `proxy:"local-public-key,omitempty"`
}

func NewEasyTier(EasyTierOption) (*EasyTier, error) {
	return nil, fmt.Errorf("EasyTier support is disabled by \"no_easytier\" build tag")
}
