//go:build !with_gvisor || no_tailscale

package outbound

import "fmt"

type Tailscale struct {
	*Base
}

type TailscaleHostForwardOption struct {
	Enabled bool   `proxy:"enabled,omitempty"`
	Mode    string `proxy:"mode,omitempty"`
	Target  string `proxy:"target,omitempty"`
	TCP     *bool  `proxy:"tcp,omitempty"`
	UDP     *bool  `proxy:"udp,omitempty"`
	Device  string `proxy:"device,omitempty"`
	MTU     uint32 `proxy:"mtu,omitempty"`
}

type TailscaleOption struct {
	BasicOption
	Name        string                     `proxy:"name"`
	Hostname    string                     `proxy:"hostname,omitempty"`
	AuthKey     string                     `proxy:"auth-key,omitempty"`
	ControlURL  string                     `proxy:"control-url,omitempty"`
	StateDir    string                     `proxy:"state-dir,omitempty"`
	Ephemeral   bool                       `proxy:"ephemeral,omitempty"`
	UDP         bool                       `proxy:"udp,omitempty"`
	MagicDNS    bool                       `proxy:"magic-dns,omitempty"`
	HostForward TailscaleHostForwardOption `proxy:"host-forward,omitempty"`

	AcceptRoutes           *bool  `proxy:"accept-routes,omitempty"`
	ExitNode               string `proxy:"exit-node,omitempty"`
	ExitNodeAllowLANAccess *bool  `proxy:"exit-node-allow-lan-access,omitempty"`
}

func NewTailscale(option TailscaleOption) (*Tailscale, error) {
	return nil, fmt.Errorf("tailscale support is disabled by \"no_tailscale\" build tag or not include \"with_gvisor\" build tag")
}
