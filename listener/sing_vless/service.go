package sing_vless

// copy and modify from https://github.com/SagerNet/sing-vmess/tree/3c1cf255413250b09a57e4ecdf1def1fa505e3cc/vless

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/metacubex/mihomo/transport/vless"
	"github.com/metacubex/mihomo/transport/vless/vision"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/sing-vmess"
	"github.com/metacubex/sing/common/auth"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"google.golang.org/protobuf/proto"
)

type Service[T comparable] struct {
	userMap  map[[16]byte]T
	userFlow map[T]string
	handler  Handler
}

type Handler interface {
	N.TCPConnectionHandler
	N.UDPConnectionHandler
	E.Handler
}

func NewService[T comparable](handler Handler) *Service[T] {
	return &Service[T]{
		handler: handler,
	}
}

func (s *Service[T]) UpdateUsers(userList []T, userUUIDList []string, userFlowList []string) {
	userMap := make(map[[16]byte]T)
	userFlowMap := make(map[T]string)
	for i, userName := range userList {
		userID, err := uuid.FromString(userUUIDList[i])
		if err != nil {
			userID = uuid.NewV5(uuid.Nil, userUUIDList[i])
		}
		userMap[userID] = userName
		userFlowMap[userName] = userFlowList[i]
	}
	s.userMap = userMap
	s.userFlow = userFlowMap
}

var _ N.TCPConnectionHandler = (*Service[int])(nil)

func (s *Service[T]) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	var version uint8
	err := binary.Read(conn, binary.BigEndian, &version)
	if err != nil {
		return err
	}
	if version != vless.Version {
		return E.New("unknown version: ", version)
	}

	var requestUUID [16]byte
	_, err = io.ReadFull(conn, requestUUID[:])
	if err != nil {
		return err
	}

	var addonsLen uint8
	err = binary.Read(conn, binary.BigEndian, &addonsLen)
	if err != nil {
		return err
	}

	var addons vless.Addons
	if addonsLen > 0 {
		addonsBytes := make([]byte, addonsLen)
		_, err = io.ReadFull(conn, addonsBytes)
		if err != nil {
			return err
		}

		err = proto.Unmarshal(addonsBytes, &addons)
		if err != nil {
			return err
		}
	}

	var command byte
	err = binary.Read(conn, binary.BigEndian, &command)
	if err != nil {
		return err
	}

	var destination M.Socksaddr
	if command != vless.CommandMux {
		destination, err = vmess.AddressSerializer.ReadAddrPort(conn)
		if err != nil {
			return err
		}
	}

	user, loaded := s.userMap[requestUUID]
	if !loaded {
		return E.New("unknown UUID: ", uuid.FromBytesOrNil(requestUUID[:]))
	}
	ctx = auth.ContextWithUser(ctx, user)
	metadata.Destination = destination

	userFlow := s.userFlow[user]
	requestFlow := addons.Flow
	if requestFlow != userFlow && requestFlow != "" {
		return E.New("flow mismatch: expected ", flowName(userFlow), ", but got ", flowName(requestFlow))
	}

	responseConn := &serverConn{ExtendedConn: bufio.NewExtendedConn(conn)}
	switch requestFlow {
	case vless.XRV:
		conn, err = vision.NewConn(responseConn, conn, requestUUID)
		if err != nil {
			return E.Cause(err, "initialize vision")
		}
	case "":
		conn = responseConn
	default:
		return E.New("unknown flow: ", requestFlow)
	}
	switch command {
	case vless.CommandTCP:
		return s.handler.NewConnection(ctx, conn, metadata)
	case vless.CommandUDP:
		if requestFlow == vless.XRV {
			return E.New(vless.XRV, " flow does not support UDP")
		}
		return s.handler.NewPacketConnection(ctx, &serverPacketConn{ExtendedConn: bufio.NewExtendedConn(conn), destination: destination}, metadata)
	case vless.CommandMux:
		return vmess.HandleMuxConnection(ctx, conn, metadata, s.handler)
	default:
		return E.New("unknown command: ", command)
	}
}

func flowName(value string) string {
	if value == "" {
		return "none"
	}
	return value
}

type serverConn struct {
	N.ExtendedConn
	responseWritten bool
}

func (c *serverConn) Write(b []byte) (n int, err error) {
	if !c.responseWritten {
		buffer := buf.NewSize(2 + len(b))
		buffer.WriteByte(vless.Version)
		buffer.WriteByte(0)
		buffer.Write(b)
		_, err = c.ExtendedConn.Write(buffer.Bytes())
		buffer.Release()
		if err == nil {
			n = len(b)
		}
		c.responseWritten = true
		return
	}
	return c.ExtendedConn.Write(b)
}

func (c *serverConn) WriteBuffer(buffer *buf.Buffer) error {
	if !c.responseWritten {
		header := buffer.ExtendHeader(2)
		header[0] = vless.Version
		header[1] = 0
		c.responseWritten = true
	}
	return c.ExtendedConn.WriteBuffer(buffer)
}

func (c *serverConn) FrontHeadroom() int {
	if c.responseWritten {
		return 0
	}
	return 2
}

func (c *serverConn) ReaderReplaceable() bool {
	return true
}

func (c *serverConn) WriterReplaceable() bool {
	return c.responseWritten
}

func (c *serverConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *serverConn) Upstream() any {
	return c.ExtendedConn
}

type serverPacketConn struct {
	N.ExtendedConn
	destination     M.Socksaddr
	readWaitOptions N.ReadWaitOptions
}

func (c *serverPacketConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readWaitOptions = options
	return false
}

func (c *serverPacketConn) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	var packetLen uint16
	err = binary.Read(c.ExtendedConn, binary.BigEndian, &packetLen)
	if err != nil {
		return
	}

	buffer = c.readWaitOptions.NewPacketBuffer()
	_, err = buffer.ReadFullFrom(c.ExtendedConn, int(packetLen))
	if err != nil {
		buffer.Release()
		return
	}
	c.readWaitOptions.PostReturn(buffer)

	destination = c.destination
	return
}

func (c *serverPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	var packetLen uint16
	err = binary.Read(c.ExtendedConn, binary.BigEndian, &packetLen)
	if err != nil {
		return
	}
	if len(p) < int(packetLen) {
		err = io.ErrShortBuffer
		return
	}
	n, err = io.ReadFull(c.ExtendedConn, p[:packetLen])
	if err != nil {
		return
	}
	if c.destination.IsFqdn() {
		addr = c.destination
	} else {
		addr = c.destination.UDPAddr()
	}
	return
}

func (c *serverPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	err = binary.Write(c.ExtendedConn, binary.BigEndian, uint16(len(p)))
	if err != nil {
		return
	}
	return c.ExtendedConn.Write(p)
}

func (c *serverPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	var packetLen uint16
	err = binary.Read(c.ExtendedConn, binary.BigEndian, &packetLen)
	if err != nil {
		return
	}

	_, err = buffer.ReadFullFrom(c.ExtendedConn, int(packetLen))
	if err != nil {
		return
	}

	destination = c.destination
	return
}

func (c *serverPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	packetLen := buffer.Len()
	binary.BigEndian.PutUint16(buffer.ExtendHeader(2), uint16(packetLen))
	return c.ExtendedConn.WriteBuffer(buffer)
}

func (c *serverPacketConn) FrontHeadroom() int {
	return 2
}

func (c *serverPacketConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *serverPacketConn) Upstream() any {
	return c.ExtendedConn
}
