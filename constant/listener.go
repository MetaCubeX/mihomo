package constant

import "net"

type Listener interface {
	RawAddress() string
	Address() string
	Close() error
}

type AdvanceListener interface {
	Close()
	Config() string
	HandleConn(conn net.Conn, in chan<- ConnContext)
}

type NewListener interface {
	Name() string
	ReCreate(tcpIn chan<- ConnContext,udpIn chan<-*PacketAdapter) error
	Close() error
	Address() string
	RawAddress() string
}

// PacketAdapter is a UDP Packet adapter for socks/redir/tun
type PacketAdapter struct {
	UDPPacket
	metadata *Metadata
}

func NewPacketAdapter(udppacket UDPPacket,metadata *Metadata)*PacketAdapter{
return &PacketAdapter{
	udppacket,
	metadata,
}
}

// Metadata returns destination metadata
func (s *PacketAdapter) Metadata() *Metadata {
	return s.metadata
}