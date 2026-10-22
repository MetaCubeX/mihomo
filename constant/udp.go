package constant

import M "github.com/metacubex/sing/common/metadata"

type UDPDestinationEncoding uint8

const (
	UDPIPOnly UDPDestinationEncoding = iota
	UDPDomain
)

type UDPReplyMode uint8

const (
	UDPReplyAddress UDPReplyMode = iota
	UDPReplyIPOnly
	UDPReplyBoundDestination
)

type UDPCapabilities struct {
	Destination UDPDestinationEncoding
	Reply       UDPReplyMode
}

// UDPRequest preserves the intended target independently of rule resolution.
// Callers must copy it before changing a request shared with another packet.
type UDPRequest struct {
	Target      M.Socksaddr
	AllowRemote bool
	SessionKey  string
}
