package trusttunnel

import (
	"encoding/binary"
	"math"
	"net"

	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/buf"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/metacubex/sing/common/rw"
)

type packetConn struct {
	httpConn
	readWaitOptions N.ReadWaitOptions
}

func (c *packetConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readWaitOptions = options
	return false
}

var (
	_ N.NetPacketConn    = (*clientPacketConn)(nil)
	_ N.FrontHeadroom    = (*clientPacketConn)(nil)
	_ N.PacketReadWaiter = (*clientPacketConn)(nil)
)

type clientPacketConn struct {
	packetConn
}

func (u *clientPacketConn) FrontHeadroom() int {
	return 4 + 16 + 2 + 16 + 2 + 1 + math.MaxUint8
}

func (u *clientPacketConn) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	buffer = u.readWaitOptions.NewPacketBuffer()
	destination, err = u.ReadPacket(buffer)
	if err != nil {
		buffer.Release()
		return nil, M.Socksaddr{}, err
	}
	u.readWaitOptions.PostReturn(buffer)
	return buffer, destination, nil
}

func (u *clientPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	err = u.waitCreated()
	if err != nil {
		return M.Socksaddr{}, err
	}
	return u.readPacketFromServer(buffer)
}

func (u *clientPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buffer := buf.With(p)
	destination, err := u.ReadPacket(buffer)
	if err != nil {
		return 0, nil, err
	}
	return buffer.Len(), destination.UDPAddr(), nil
}

func (u *clientPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return u.writePacketToServer(buffer, destination)
}

func (u *clientPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	err = u.WritePacket(buf.As(p), M.SocksaddrFromNet(addr))
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (u *clientPacketConn) readPacketFromServer(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	header := buf.NewSize(4 + 16 + 2 + 16 + 2)
	defer header.Release()
	_, err = header.ReadFullFrom(u.body, header.Cap())
	if err != nil {
		return
	}
	var length uint32
	common.Must(binary.Read(header, binary.BigEndian, &length))
	var sourceAddressBuffer [16]byte
	common.Must1(header.Read(sourceAddressBuffer[:]))
	destination.Addr = parse16BytesIP(sourceAddressBuffer)
	common.Must(binary.Read(header, binary.BigEndian, &destination.Port))
	common.Must(rw.SkipN(header, 16+2)) // To local address:port
	payloadLen := int(length) - (16 + 2 + 16 + 2)
	if payloadLen < 0 {
		return M.Socksaddr{}, E.New("invalid udp length: ", length)
	}
	_, err = buffer.ReadFullFrom(u.body, payloadLen)
	return
}

func (u *clientPacketConn) writePacketToServer(buffer *buf.Buffer, source M.Socksaddr) error {
	defer buffer.Release()
	if !source.IsIP() {
		return E.New("only support IP")
	}
	appName := AppName
	if len(appName) > math.MaxUint8 {
		appName = appName[:math.MaxUint8]
	}
	payloadLen := buffer.Len()
	headerLen := 4 + 16 + 2 + 16 + 2 + 1 + len(appName)
	lengthField := uint32(16 + 2 + 16 + 2 + 1 + len(appName) + payloadLen)
	destinationAddress := buildPaddingIP(source.Addr)

	var (
		header         *buf.Buffer
		headerInBuffer bool
	)
	if buffer.Start() >= headerLen {
		headerBytes := buffer.ExtendHeader(headerLen)
		header = buf.With(headerBytes)
		headerInBuffer = true
	} else {
		header = buf.NewSize(headerLen)
		defer header.Release()
	}
	common.Must(binary.Write(header, binary.BigEndian, lengthField))
	common.Must(header.WriteZeroN(16 + 2)) // Source address:port (unknown)
	common.Must1(header.Write(destinationAddress[:]))
	common.Must(binary.Write(header, binary.BigEndian, source.Port))
	common.Must(binary.Write(header, binary.BigEndian, uint8(len(appName))))
	common.Must1(header.WriteString(appName))
	if !headerInBuffer {
		_, err := u.writer.Write(header.Bytes())
		if err != nil {
			return err
		}
	}
	_, err := u.writer.Write(buffer.Bytes())
	if err != nil {
		return err
	}
	if u.flusher != nil {
		u.flusher.Flush()
	}
	return nil
}

var (
	_ N.NetPacketConn    = (*serverPacketConn)(nil)
	_ N.FrontHeadroom    = (*serverPacketConn)(nil)
	_ N.PacketReadWaiter = (*serverPacketConn)(nil)
)

type serverPacketConn struct {
	packetConn
}

func (u *serverPacketConn) FrontHeadroom() int {
	return 4 + 16 + 2 + 16 + 2
}

func (u *serverPacketConn) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	buffer = u.readWaitOptions.NewPacketBuffer()
	destination, err = u.ReadPacket(buffer)
	if err != nil {
		buffer.Release()
		return nil, M.Socksaddr{}, err
	}
	u.readWaitOptions.PostReturn(buffer)
	return buffer, destination, nil
}

func (u *serverPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	err = u.waitCreated()
	if err != nil {
		return M.Socksaddr{}, err
	}
	return u.readPacketFromClient(buffer)
}

func (u *serverPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buffer := buf.With(p)
	destination, err := u.ReadPacket(buffer)
	if err != nil {
		return 0, nil, err
	}
	return buffer.Len(), destination.UDPAddr(), nil
}

func (u *serverPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return u.writePacketToClient(buffer, destination)
}

func (u *serverPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	err = u.WritePacket(buf.As(p), M.SocksaddrFromNet(addr))
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (u *serverPacketConn) readPacketFromClient(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	header := buf.NewSize(4 + 16 + 2 + 16 + 2 + 1)
	defer header.Release()
	_, err = header.ReadFullFrom(u.body, header.Cap())
	if err != nil {
		return
	}
	var length uint32
	common.Must(binary.Read(header, binary.BigEndian, &length))
	var sourceAddressBuffer [16]byte
	common.Must1(header.Read(sourceAddressBuffer[:]))
	var sourcePort uint16
	common.Must(binary.Read(header, binary.BigEndian, &sourcePort))
	_ = sourcePort
	var destinationAddressBuffer [16]byte
	common.Must1(header.Read(destinationAddressBuffer[:]))
	destination.Addr = parse16BytesIP(destinationAddressBuffer)
	common.Must(binary.Read(header, binary.BigEndian, &destination.Port))
	var appNameLen uint8
	common.Must(binary.Read(header, binary.BigEndian, &appNameLen))
	if appNameLen > 0 {
		err = rw.SkipN(u.body, int(appNameLen))
		if err != nil {
			return M.Socksaddr{}, err
		}
	}
	payloadLen := int(length) - (16 + 2 + 16 + 2 + 1 + int(appNameLen))
	if payloadLen < 0 {
		return M.Socksaddr{}, E.New("invalid udp length: ", length)
	}
	_, err = buffer.ReadFullFrom(u.body, payloadLen)
	return
}

func (u *serverPacketConn) writePacketToClient(buffer *buf.Buffer, source M.Socksaddr) error {
	defer buffer.Release()
	if !source.IsIP() {
		return E.New("only support IP")
	}
	payloadLen := buffer.Len()
	headerLen := 4 + 16 + 2 + 16 + 2
	lengthField := uint32(16 + 2 + 16 + 2 + payloadLen)
	sourceAddress := buildPaddingIP(source.Addr)
	var destinationAddress [16]byte
	var destinationPort uint16
	var (
		header         *buf.Buffer
		headerInBuffer bool
	)
	if buffer.Start() >= headerLen {
		headerBytes := buffer.ExtendHeader(headerLen)
		header = buf.With(headerBytes)
		headerInBuffer = true
	} else {
		header = buf.NewSize(headerLen)
		defer header.Release()
	}
	common.Must(binary.Write(header, binary.BigEndian, lengthField))
	common.Must1(header.Write(sourceAddress[:]))
	common.Must(binary.Write(header, binary.BigEndian, source.Port))
	common.Must1(header.Write(destinationAddress[:]))
	common.Must(binary.Write(header, binary.BigEndian, destinationPort))
	if !headerInBuffer {
		_, err := u.writer.Write(header.Bytes())
		if err != nil {
			return err
		}
	}
	_, err := u.writer.Write(buffer.Bytes())
	if err != nil {
		return err
	}
	if u.flusher != nil {
		u.flusher.Flush()
	}
	return nil
}
