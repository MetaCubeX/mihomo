package core

import (
	"time"
)

const (
	protocolVersion   = uint8(3)
	protocolVersionV2 = uint8(2)
	protocolTimeout   = 10 * time.Second

	closeErrorCodeGeneric  = 0
	closeErrorCodeProtocol = 1
	closeErrorCodeAuth     = 2
)

type transmissionRate struct {
	SendBPS uint64
	RecvBPS uint64
}

type clientHello struct {
	Rate    transmissionRate
	AuthLen uint16 `struc:"sizeof=Auth"`
	Auth    []byte
}

type serverHello struct {
	OK         bool
	Rate       transmissionRate
	MessageLen uint16 `struc:"sizeof=Message"`
	Message    string
}

type clientRequest struct {
	UDP     bool
	HostLen uint16 `struc:"sizeof=Host"`
	Host    string
	Port    uint16
}

type serverResponse struct {
	OK           bool
	UDPSessionID uint32
	MessageLen   uint16 `struc:"sizeof=Message"`
	Message      string
}

type udpMessage struct {
	SessionID uint32
	HostLen   uint16 `struc:"sizeof=Host"`
	Host      string
	Port      uint16
	MsgID     uint16 // doesn't matter when not fragmented, but must not be 0 when fragmented
	FragID    uint8  // doesn't matter when not fragmented, starts at 0 when fragmented
	FragCount uint8  // must be 1 when not fragmented
	DataLen   uint16 `struc:"sizeof=Data"`
	Data      []byte
}

func (m udpMessage) HeaderSize() int {
	return 4 + 2 + len(m.Host) + 2 + 2 + 1 + 1 + 2
}

func (m udpMessage) Size() int {
	return m.HeaderSize() + len(m.Data)
}

type udpMessageV2 struct {
	SessionID uint32
	HostLen   uint16 `struc:"sizeof=Host"`
	Host      string
	Port      uint16
	DataLen   uint16 `struc:"sizeof=Data"`
	Data      []byte
}
