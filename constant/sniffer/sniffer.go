package sniffer

import "github.com/metacubex/mihomo/constant"

type Sniffer interface {
	SupportNetwork() constant.NetWork
	// SniffData must not change input bytes
	SniffData(bytes []byte) (string, error)
	Protocol() string
	SupportPort(port uint16) bool
}

// ProtocolSniffer reports the application protocol carried by a connection
// instead of the domain it is heading to. Its result never overrides the
// destination, it only tags the metadata for the PROTOCOL rule.
type ProtocolSniffer interface {
	Sniffer
	// SniffProtocol must not change input bytes.
	// network tells which kind of traffic the bytes came from, so that
	// stream-only and packet-only detectors are not applied to the wrong one.
	SniffProtocol(network constant.NetWork, bytes []byte) (string, error)
}

type ReplaceDomain func(metadata *constant.Metadata, host string)

type MultiPacketSniffer interface {
	WrapperSender(packetSender constant.PacketSender, replaceDomain ReplaceDomain) constant.PacketSender
}

const (
	TLS Type = iota
	HTTP
	QUIC
	BitTorrent
)

var (
	List = []Type{TLS, HTTP, QUIC, BitTorrent}
)

type Type int

func (rt Type) String() string {
	switch rt {
	case TLS:
		return "TLS"
	case HTTP:
		return "HTTP"
	case QUIC:
		return "QUIC"
	case BitTorrent:
		// config lookup compares against strings.ToUpper of the user provided
		// name, so this has to stay uppercase like the other entries
		return "BITTORRENT"
	default:
		return "Unknown"
	}
}
