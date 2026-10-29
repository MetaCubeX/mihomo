package constant

import (
	"strconv"
	"strings"

	M "github.com/metacubex/sing/common/metadata"
)

// UDPConfig is captured by a source group before creating any associations.
// Changing the defaults must not reinterpret the group's existing NAT state.
type UDPConfig struct {
	RemoteResolve bool
	Mapping       UDPMapping
}

type UDPSessionKey struct {
	Source      string
	Mapping     UDPMapping
	Destination M.Socksaddr
}

func NewUDPSessionKey(source string, mapping UDPMapping, origin M.Socksaddr) UDPSessionKey {
	key := UDPSessionKey{Source: source, Mapping: mapping}
	if mapping == UDPEndpointIndependent {
		return key
	}
	origin = origin.Unwrap()
	if origin.IsFqdn() {
		origin.Fqdn = strings.ToLower(strings.TrimSuffix(origin.Fqdn, "."))
	}
	if mapping == UDPAddressDependent {
		origin.Port = 0
	}
	key.Destination = origin
	return key
}

// String is hash material, not the lookup key. The length prefix keeps inbound
// namespaces unambiguous even when they contain address or mode separators.
func (k UDPSessionKey) String() string {
	if k.Source == "" {
		return ""
	}
	material := strconv.Itoa(len(k.Source)) + ":" + k.Source + ":" + k.Mapping.String()
	if k.Mapping != UDPEndpointIndependent {
		material += ":" + k.Destination.String()
	}
	return material
}

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
