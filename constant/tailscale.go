package constant

import (
	"context"
	"net/netip"
)

// TailscaleExitNode is an offered and approved exit node visible to one outbound.
// Online describes control-plane presence, not a connectivity guarantee.
type TailscaleExitNode struct {
	ID             string       `json:"id"`
	HostName       string       `json:"hostName"`
	DNSName        string       `json:"dnsName"`
	TailscaleIPs   []netip.Addr `json:"tailscaleIPs"`
	Online         bool         `json:"online"`
	ExitNodeOption bool         `json:"exitNodeOption"`
	ExitNode       bool         `json:"exitNode"`
}

// TailscaleExitNodes describes discovery readiness separately from an empty list.
type TailscaleExitNodes struct {
	State        string              `json:"state"`
	BackendState string              `json:"backendState,omitempty"`
	ExitNodes    []TailscaleExitNode `json:"exitNodes"`
}

// TailscaleExitNodeProvider is an optional capability of a concrete outbound.
// Queries must not start the outbound or change its authentication or preferences.
type TailscaleExitNodeProvider interface {
	TailscaleExitNodes(context.Context) (*TailscaleExitNodes, error)
}
