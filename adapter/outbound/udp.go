package outbound

import (
	"context"
	"errors"
	"fmt"

	C "github.com/metacubex/mihomo/constant"

	M "github.com/metacubex/sing/common/metadata"
)

type udpPreparation struct {
	initial      M.Socksaddr
	capabilities C.UDPCapabilities
	allowRemote  bool
	resolveUDP   func(context.Context, *C.Metadata) error
}

func validateUDPRequest(metadata *C.Metadata) error {
	if metadata == nil {
		return errors.New("UDP request is required")
	}
	if metadata.UDP == nil {
		// External library callers may omit UDPRequest. Preserve their local
		// resolution behavior without remote permission or an XUDP identity.
		metadata.UDP = &C.UDPRequest{Target: M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort)}
	}
	return nil
}

func remoteUDPTarget(target M.Socksaddr) (M.Socksaddr, error) {
	// A mixed IP/FQDN address has different meanings to different encoders.
	if !target.IsValid() || target.IsIP() && target.Fqdn != "" {
		return M.Socksaddr{}, errors.New("UDP target is invalid")
	}
	return target.Unwrap(), nil
}

func (p *udpPreparation) PrepareUDP(ctx context.Context, metadata *C.Metadata) (M.Socksaddr, error) {
	if err := validateUDPRequest(metadata); err != nil {
		return M.Socksaddr{}, err
	}
	// Permission belongs to this connection, not to a later packet or a group
	// that may have selected a different adapter since the association opened.
	if p.allowRemote && p.capabilities.Destination == C.UDPDomain {
		return remoteUDPTarget(metadata.UDP.Target)
	}

	local := metadata.Clone()
	// Initial setup still runs the adapter's original preparation. For later
	// literal-IP packets, preserve the sender's old Host guard (some helpers
	// also start a tunnel or validate its address family).
	if local.Host != "" {
		if err := p.resolveUDP(ctx, local); err != nil {
			return M.Socksaddr{}, err
		}
	}
	if !local.DstIP.IsValid() {
		return M.Socksaddr{}, fmt.Errorf("UDP destination IP is invalid: %s", local.RemoteAddress())
	}
	return M.Socksaddr{Addr: local.DstIP.Unmap(), Port: local.DstPort}, nil
}

func (p *udpPreparation) InitialDestination() M.Socksaddr {
	return p.initial
}

func (p *udpPreparation) UDPCapabilities() C.UDPCapabilities {
	return p.capabilities
}
