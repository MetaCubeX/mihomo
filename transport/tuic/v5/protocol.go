package v5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/metacubex/quic-go"
)

type BufferedReader interface {
	io.Reader
	io.ByteReader
}

type BufferedWriter interface {
	io.Writer
	io.ByteWriter
}

type CommandType byte

const (
	AuthenticateType = CommandType(0x00)
	ConnectType      = CommandType(0x01)
	PacketType       = CommandType(0x02)
	DissociateType   = CommandType(0x03)
	HeartbeatType    = CommandType(0x04)
)

const VER byte = 0x05

func (c CommandType) String() string {
	switch c {
	case AuthenticateType:
		return "Authenticate"
	case ConnectType:
		return "Connect"
	case PacketType:
		return "Packet"
	case DissociateType:
		return "Dissociate"
	case HeartbeatType:
		return "Heartbeat"
	default:
		return fmt.Sprintf("UnknowCommand: %#x", byte(c))
	}
}

func (c CommandType) BytesLen() int {
	return 1
}

type CommandHead struct {
	VER  byte
	TYPE CommandType
}

func NewCommandHead(TYPE CommandType) CommandHead {
	return CommandHead{
		VER:  VER,
		TYPE: TYPE,
	}
}

func ReadCommandHead(reader BufferedReader) (c CommandHead, err error) {
	c.VER, err = reader.ReadByte()
	if err != nil {
		return
	}
	TYPE, err := reader.ReadByte()
	if err != nil {
		return
	}
	c.TYPE = CommandType(TYPE)
	return
}

func (c CommandHead) WriteTo(writer BufferedWriter) (err error) {
	err = writer.WriteByte(c.VER)
	if err != nil {
		return
	}
	err = writer.WriteByte(byte(c.TYPE))
	if err != nil {
		return
	}
	return
}

func (c CommandHead) BytesLen() int {
	return 1 + c.TYPE.BytesLen()
}

type Authenticate struct {
	CommandHead
	UUID  [16]byte
	TOKEN [32]byte
}

func NewAuthenticate(UUID [16]byte, TOKEN [32]byte) Authenticate {
	return Authenticate{
		CommandHead: NewCommandHead(AuthenticateType),
		UUID:        UUID,
		TOKEN:       TOKEN,
	}
}

func ReadAuthenticateWithHead(head CommandHead, reader BufferedReader) (c Authenticate, err error) {
	c.CommandHead = head
	if c.CommandHead.TYPE != AuthenticateType {
		err = fmt.Errorf("error command type: %s", c.CommandHead.TYPE)
		return
	}
	_, err = io.ReadFull(reader, c.UUID[:])
	if err != nil {
		return
	}
	_, err = io.ReadFull(reader, c.TOKEN[:])
	if err != nil {
		return
	}
	return
}

func ReadAuthenticate(reader BufferedReader) (c Authenticate, err error) {
	head, err := ReadCommandHead(reader)
	if err != nil {
		return
	}
	return ReadAuthenticateWithHead(head, reader)
}

func GenToken(state quic.ConnectionState, uuid [16]byte, password string) (token [32]byte, err error) {
	var tokenBytes []byte
	tokenBytes, err = state.TLS.ExportKeyingMaterial(utils.StringFromImmutableBytes(uuid[:]), utils.ImmutableBytesFromString(password), 32)
	if err != nil {
		return
	}
	copy(token[:], tokenBytes)
	return
}

func (c Authenticate) WriteTo(writer BufferedWriter) (err error) {
	err = c.CommandHead.WriteTo(writer)
	if err != nil {
		return
	}
	_, err = writer.Write(c.UUID[:])
	if err != nil {
		return
	}
	_, err = writer.Write(c.TOKEN[:])
	if err != nil {
		return
	}
	return
}

func (c Authenticate) BytesLen() int {
	return c.CommandHead.BytesLen() + 16 + 32
}

type Connect struct {
	CommandHead
	ADDR Address
}

func NewConnect(ADDR Address) Connect {
	return Connect{
		CommandHead: NewCommandHead(ConnectType),
		ADDR:        ADDR,
	}
}

func ReadConnectWithHead(head CommandHead, reader BufferedReader) (c Connect, err error) {
	c.CommandHead = head
	if c.CommandHead.TYPE != ConnectType {
		err = fmt.Errorf("error command type: %s", c.CommandHead.TYPE)
		return
	}
	c.ADDR, err = ReadAddress(reader)
	if err != nil {
		return
	}
	return
}

func ReadConnect(reader BufferedReader) (c Connect, err error) {
	head, err := ReadCommandHead(reader)
	if err != nil {
		return
	}
	return ReadConnectWithHead(head, reader)
}

func (c Connect) WriteTo(writer BufferedWriter) (err error) {
	err = c.CommandHead.WriteTo(writer)
	if err != nil {
		return
	}
	err = c.ADDR.WriteTo(writer)
	if err != nil {
		return
	}
	return
}

func (c Connect) BytesLen() int {
	return c.CommandHead.BytesLen() + c.ADDR.BytesLen()
}

type Packet struct {
	CommandHead
	ASSOC_ID   uint16
	PKT_ID     uint16
	FRAG_TOTAL uint8
	FRAG_ID    uint8
	SIZE       uint16
	ADDR       Address
	DATA       []byte
}

func NewPacket(ASSOC_ID uint16, PKT_ID uint16, FRGA_TOTAL uint8, FRAG_ID uint8, SIZE uint16, ADDR Address, DATA []byte) Packet {
	return Packet{
		CommandHead: NewCommandHead(PacketType),
		ASSOC_ID:    ASSOC_ID,
		PKT_ID:      PKT_ID,
		FRAG_ID:     FRAG_ID,
		FRAG_TOTAL:  FRGA_TOTAL,
		SIZE:        SIZE,
		ADDR:        ADDR,
		DATA:        DATA,
	}
}

func ReadPacketWithHead(head CommandHead, reader BufferedReader) (c Packet, err error) {
	c.CommandHead = head
	if c.CommandHead.TYPE != PacketType {
		err = fmt.Errorf("error command type: %s", c.CommandHead.TYPE)
		return
	}
	err = binary.Read(reader, binary.BigEndian, &c.ASSOC_ID)
	if err != nil {
		return
	}
	err = binary.Read(reader, binary.BigEndian, &c.PKT_ID)
	if err != nil {
		return
	}
	err = binary.Read(reader, binary.BigEndian, &c.FRAG_TOTAL)
	if err != nil {
		return
	}
	err = binary.Read(reader, binary.BigEndian, &c.FRAG_ID)
	if err != nil {
		return
	}
	err = binary.Read(reader, binary.BigEndian, &c.SIZE)
	if err != nil {
		return
	}
	c.ADDR, err = ReadAddress(reader)
	if err != nil {
		return
	}
	c.DATA = make([]byte, c.SIZE)
	_, err = io.ReadFull(reader, c.DATA)
	if err != nil {
		return
	}
	return
}

func ReadPacket(reader BufferedReader) (c Packet, err error) {
	head, err := ReadCommandHead(reader)
	if err != nil {
		return
	}
	return ReadPacketWithHead(head, reader)
}

func (c Packet) WriteTo(writer BufferedWriter) (err error) {
	err = c.CommandHead.WriteTo(writer)
	if err != nil {
		return
	}
	err = binary.Write(writer, binary.BigEndian, c.ASSOC_ID)
	if err != nil {
		return
	}
	err = binary.Write(writer, binary.BigEndian, c.PKT_ID)
	if err != nil {
		return
	}
	err = binary.Write(writer, binary.BigEndian, c.FRAG_TOTAL)
	if err != nil {
		return
	}
	err = binary.Write(writer, binary.BigEndian, c.FRAG_ID)
	if err != nil {
		return
	}
	err = binary.Write(writer, binary.BigEndian, c.SIZE)
	if err != nil {
		return
	}
	err = c.ADDR.WriteTo(writer)
	if err != nil {
		return
	}
	_, err = writer.Write(c.DATA)
	if err != nil {
		return
	}
	return
}

func (c Packet) BytesLen() int {
	return c.CommandHead.BytesLen() + 4 + 2 + c.ADDR.BytesLen() + len(c.DATA)
}

var PacketOverHead = NewPacket(0, 0, 0, 0, 0, NewAddressAddrPort(netip.AddrPortFrom(netip.IPv6Unspecified(), 0)), nil).BytesLen()

type Dissociate struct {
	CommandHead
	ASSOC_ID uint16
}

func NewDissociate(ASSOC_ID uint16) Dissociate {
	return Dissociate{
		CommandHead: NewCommandHead(DissociateType),
		ASSOC_ID:    ASSOC_ID,
	}
}

func ReadDissociateWithHead(head CommandHead, reader BufferedReader) (c Dissociate, err error) {
	c.CommandHead = head
	if c.CommandHead.TYPE != DissociateType {
		err = fmt.Errorf("error command type: %s", c.CommandHead.TYPE)
		return
	}
	err = binary.Read(reader, binary.BigEndian, &c.ASSOC_ID)
	if err != nil {
		return
	}
	return
}

func ReadDissociate(reader BufferedReader) (c Dissociate, err error) {
	head, err := ReadCommandHead(reader)
	if err != nil {
		return
	}
	return ReadDissociateWithHead(head, reader)
}

func (c Dissociate) WriteTo(writer BufferedWriter) (err error) {
	err = c.CommandHead.WriteTo(writer)
	if err != nil {
		return
	}
	err = binary.Write(writer, binary.BigEndian, c.ASSOC_ID)
	if err != nil {
		return
	}
	return
}

func (c Dissociate) BytesLen() int {
	return c.CommandHead.BytesLen() + 4
}

type Heartbeat struct {
	CommandHead
}

func NewHeartbeat() Heartbeat {
	return Heartbeat{
		CommandHead: NewCommandHead(HeartbeatType),
	}
}

func ReadHeartbeatWithHead(head CommandHead, reader BufferedReader) (c Heartbeat, err error) {
	c.CommandHead = head
	if c.CommandHead.TYPE != HeartbeatType {
		err = fmt.Errorf("error command type: %s", c.CommandHead.TYPE)
		return
	}
	return
}

func ReadHeartbeat(reader BufferedReader) (c Heartbeat, err error) {
	head, err := ReadCommandHead(reader)
	if err != nil {
		return
	}
	return ReadHeartbeatWithHead(head, reader)
}

// Addr types
const (
	AtypDomainName byte = 0
	AtypIPv4       byte = 1
	AtypIPv6       byte = 2
	AtypNone       byte = 255 // Address type None is used in Packet commands that is not the first fragment of a UDP packet.
)

type Address struct {
	TYPE byte
	ADDR []byte
	PORT uint16
}

func NewAddress(metadata *C.Metadata) Address {
	var addrType byte
	var addr []byte
	switch metadata.AddrType() {
	case socks5.AtypIPv4:
		addrType = AtypIPv4
		addr = metadata.DstIP.AsSlice()
	case socks5.AtypIPv6:
		addrType = AtypIPv6
		addr = metadata.DstIP.AsSlice()
	case socks5.AtypDomainName:
		addrType = AtypDomainName
		addr = make([]byte, len(metadata.Host)+1)
		addr[0] = byte(len(metadata.Host))
		copy(addr[1:], metadata.Host)
	}

	return Address{
		TYPE: addrType,
		ADDR: addr,
		PORT: metadata.DstPort,
	}
}

func NewAddressNetAddr(addr net.Addr) (Address, error) {
	if addr, ok := addr.(interface{ AddrPort() netip.AddrPort }); ok {
		if addrPort := addr.AddrPort(); addrPort.IsValid() { // sing's M.Socksaddr maybe return an invalid AddrPort if it's a DomainName
			return NewAddressAddrPort(addrPort), nil
		}
	}
	addrStr := addr.String()
	if addrPort, err := netip.ParseAddrPort(addrStr); err == nil {
		return NewAddressAddrPort(addrPort), nil
	}
	metadata := &C.Metadata{}
	if err := metadata.SetRemoteAddress(addrStr); err != nil {
		return Address{}, err
	}
	return NewAddress(metadata), nil
}

func NewAddressAddrPort(addrPort netip.AddrPort) Address {
	var addrType byte
	port := addrPort.Port()
	addr := addrPort.Addr().Unmap()
	if addr.Is4() {
		addrType = AtypIPv4
	} else {
		addrType = AtypIPv6
	}
	return Address{
		TYPE: addrType,
		ADDR: addr.AsSlice(),
		PORT: port,
	}
}

func ReadAddress(reader BufferedReader) (c Address, err error) {
	c.TYPE, err = reader.ReadByte()
	if err != nil {
		return
	}
	switch c.TYPE {
	case AtypIPv4:
		c.ADDR = make([]byte, net.IPv4len)
		_, err = io.ReadFull(reader, c.ADDR)
		if err != nil {
			return
		}
	case AtypIPv6:
		c.ADDR = make([]byte, net.IPv6len)
		_, err = io.ReadFull(reader, c.ADDR)
		if err != nil {
			return
		}
	case AtypDomainName:
		var addrLen byte
		addrLen, err = reader.ReadByte()
		if err != nil {
			return
		}
		c.ADDR = make([]byte, addrLen+1)
		c.ADDR[0] = addrLen
		_, err = io.ReadFull(reader, c.ADDR[1:])
		if err != nil {
			return
		}
	}

	if c.TYPE == AtypNone {
		return
	}
	err = binary.Read(reader, binary.BigEndian, &c.PORT)
	if err != nil {
		return
	}
	return
}

func (c Address) WriteTo(writer BufferedWriter) (err error) {
	err = writer.WriteByte(c.TYPE)
	if err != nil {
		return
	}
	if c.TYPE == AtypNone {
		return
	}
	_, err = writer.Write(c.ADDR[:])
	if err != nil {
		return
	}
	err = binary.Write(writer, binary.BigEndian, c.PORT)
	if err != nil {
		return
	}
	return
}

func (c Address) String() string {
	switch c.TYPE {
	case AtypDomainName:
		return net.JoinHostPort(string(c.ADDR[1:]), strconv.Itoa(int(c.PORT)))
	default:
		addr, _ := netip.AddrFromSlice(c.ADDR)
		addrPort := netip.AddrPortFrom(addr, c.PORT)
		return addrPort.String()
	}
}

func (c Address) SocksAddr() socks5.Addr {
	addr := make([]byte, 1+len(c.ADDR)+2)
	switch c.TYPE {
	case AtypIPv4:
		addr[0] = socks5.AtypIPv4
	case AtypIPv6:
		addr[0] = socks5.AtypIPv6
	case AtypDomainName:
		addr[0] = socks5.AtypDomainName
	}
	copy(addr[1:], c.ADDR)
	binary.BigEndian.PutUint16(addr[len(addr)-2:], c.PORT)
	return addr
}

func (c Address) UDPAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   c.ADDR,
		Port: int(c.PORT),
		Zone: "",
	}
}

func (c Address) BytesLen() int {
	return 1 + len(c.ADDR) + 2
}

const (
	ProtocolError         = quic.ApplicationErrorCode(0xfffffff0)
	AuthenticationFailed  = quic.ApplicationErrorCode(0xfffffff1)
	AuthenticationTimeout = quic.ApplicationErrorCode(0xfffffff2)
	BadCommand            = quic.ApplicationErrorCode(0xfffffff3)
)
