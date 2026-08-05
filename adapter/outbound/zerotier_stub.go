//go:build no_zerotier

package outbound

import "fmt"

type ZeroTier struct {
	*Base
}

type ZeroTierOption struct {
	BasicOption
	Name              string                `proxy:"name"`
	Network           string                `proxy:"network"`
	StateDir          string                `proxy:"state-dir,omitempty"`
	Planet            string                `proxy:"planet,omitempty"`
	MTU               int                   `proxy:"mtu,omitempty"`
	IPStack           IPStackOption         `proxy:"ip-stack,omitempty"`
	PhysicalMTU       int                   `proxy:"physical-mtu,omitempty"`
	UDP               bool                  `proxy:"udp,omitempty"`
	RemoteDnsResolve  bool                  `proxy:"remote-dns-resolve,omitempty"`
	Dns               []string              `proxy:"dns,omitempty"`
	LowBandwidth      bool                  `proxy:"low-bandwidth,omitempty"`
	EncryptedHello    bool                  `proxy:"encrypted-hello,omitempty"`
	PrimaryPort       int                   `proxy:"primary-port,omitempty"`
	SecondaryPort     int                   `proxy:"secondary-port,omitempty"`
	TCPFallbackMode   string                `proxy:"tcp-fallback-mode,omitempty"`
	TCPFallbackRelay  string                `proxy:"tcp-fallback-relay,omitempty"`
	Orbit             []ZeroTierOrbitOption `proxy:"orbit,omitempty"`
	RemoteTraceTarget string                `proxy:"remote-trace-target,omitempty"`
	RemoteTraceLevel  uint64                `proxy:"remote-trace-level,omitempty"`
}

type ZeroTierOrbitOption struct {
	World string `proxy:"world"`
	Seed  string `proxy:"seed"`
}

func NewZeroTier(ZeroTierOption) (*ZeroTier, error) {
	return nil, fmt.Errorf("ZeroTier support is disabled by \"no_zerotier\" build tag")
}
