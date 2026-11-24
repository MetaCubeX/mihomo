//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/ipn/ipnstate"
)

const tailscaleDiscoveryTimeout = 5 * time.Second

// The client is published only after start has initialized the server. In
// particular, discovery must never call Server.LocalClient on an unstarted
// server: LocalClient itself starts tsnet.
type tailscaleDiscovery struct {
	mu     sync.Mutex
	state  string
	status func(context.Context) (*ipnstate.Status, error)
}

func (d *tailscaleDiscovery) update(state string, status func(context.Context) (*ipnstate.Status, error)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state != "Closed" {
		d.state, d.status = state, status
	}
}

func (d *tailscaleDiscovery) query(ctx, lifetime context.Context) (*C.TailscaleExitNodes, error) {
	d.mu.Lock()
	state, status := d.state, d.status
	d.mu.Unlock()
	if state == "" {
		state = "NotStarted"
	}
	result := &C.TailscaleExitNodes{State: state, ExitNodes: []C.TailscaleExitNode{}}
	if lifetime.Err() != nil {
		result.State = "Closed"
		return result, nil
	}
	if status == nil {
		if state == "Error" {
			return nil, errors.New("tailscale initialization failed")
		}
		return result, nil
	}

	ctx, cancel := context.WithTimeout(ctx, tailscaleDiscoveryTimeout)
	defer cancel()
	// Go 1.20 does not have context.AfterFunc. Bound the lifetime of this
	// cancellation bridge by the request, including when Status fails early.
	go func() {
		select {
		case <-lifetime.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	s, err := status(ctx)
	if lifetime.Err() != nil {
		result.State = "Closed"
		return result, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, errors.New("tailscale status query failed")
	}
	if s == nil {
		return nil, errors.New("tailscale status is unavailable")
	}
	result.BackendState = s.BackendState
	result.State = s.BackendState
	if s.BackendState != ipn.Running.String() {
		return result, nil
	}
	// A Running backend may still have only a lite netmap. Self.Online is
	// set only after a streamed map response, unlike the backend state.
	// With no live control connection, do not present cached peers as a
	// freshly synchronized (possibly empty) list.
	if s.Self == nil || !s.Self.InNetworkMap {
		result.State = "Synchronizing"
		return result, nil
	}
	if !s.Self.Online {
		result.State = "Disconnected"
		return result, nil
	}
	result.State = "Ready"
	for _, peer := range s.Peer {
		// ExitNodeOption is derived from approved AllowedIPs, not merely
		// advertised routes. Ignore stale engine-only and expired peers.
		if peer == nil || !peer.InNetworkMap || !peer.ExitNodeOption || peer.Expired || peer.ID == "" || len(peer.TailscaleIPs) == 0 {
			continue
		}
		result.ExitNodes = append(result.ExitNodes, C.TailscaleExitNode{
			ID:             string(peer.ID),
			HostName:       peer.HostName,
			DNSName:        peer.DNSName,
			TailscaleIPs:   append([]netip.Addr(nil), peer.TailscaleIPs...),
			Online:         peer.Online,
			ExitNodeOption: peer.ExitNodeOption,
			ExitNode:       peer.ExitNode,
		})
	}
	sort.Slice(result.ExitNodes, func(i, j int) bool { return result.ExitNodes[i].ID < result.ExitNodes[j].ID })
	return result, nil
}

func (t *Tailscale) TailscaleExitNodes(ctx context.Context) (*C.TailscaleExitNodes, error) {
	return t.discovery.query(ctx, t.ctx)
}

var _ C.TailscaleExitNodeProvider = (*Tailscale)(nil)
