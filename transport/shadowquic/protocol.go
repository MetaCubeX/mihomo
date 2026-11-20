package shadowquic

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

const (
	CommandConnect           byte = 0x01
	CommandBind              byte = 0x02
	CommandAssociateDatagram byte = 0x03
	CommandAssociateStream   byte = 0x04
	CommandAuthenticate      byte = 0x05
	CommandExtension         byte = 0xff
)

const maxUDPPacketSize = 0xffff

var (
	errInvalidAddress  = errors.New("shadowquic: invalid address")
	errInvalidDatagram = errors.New("shadowquic: invalid datagram")
	errPacketTooLarge  = errors.New("shadowquic: packet too large")
)

func MetadataAddr(metadata *C.Metadata) (socks5.Addr, error) {
	addr := socks5.ParseAddr(metadata.RemoteAddress())
	if addr == nil {
		return nil, fmt.Errorf("%w: %s", errInvalidAddress, metadata.RemoteAddress())
	}
	return addr, nil
}

func UnspecifiedAddr() socks5.Addr {
	return socks5.AddrFromStdAddrPort(netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
}

func AddrFromNetAddr(addr net.Addr) (socks5.Addr, error) {
	if addr == nil {
		return nil, errInvalidAddress
	}
	socksAddr := socks5.ParseAddrToSocksAddr(addr)
	if socksAddr == nil {
		socksAddr = socks5.ParseAddr(addr.String())
	}
	if socksAddr == nil {
		return nil, fmt.Errorf("%w: %s", errInvalidAddress, addr.String())
	}
	return socksAddr, nil
}

func AddrToNetAddr(addr socks5.Addr) net.Addr {
	return addr.NetAddr()
}

func WriteRequest(w io.Writer, command byte, addr socks5.Addr) error {
	if addr == nil {
		return errInvalidAddress
	}
	if _, err := w.Write([]byte{command}); err != nil {
		return err
	}
	_, err := w.Write(addr)
	return err
}

func ReadCommand(r io.Reader) (byte, error) {
	return socks5.ReadByte(r)
}

func ReadRequestAddr(r io.Reader) (socks5.Addr, error) {
	return socks5.ReadAddr0(r)
}

func ReadRequest(r io.Reader) (byte, socks5.Addr, error) {
	command, err := ReadCommand(r)
	if err != nil {
		return 0, nil, err
	}
	addr, err := ReadRequestAddr(r)
	if err != nil {
		return 0, nil, err
	}
	return command, addr, nil
}

func WriteUDPControl(w io.Writer, addr socks5.Addr, id uint16) error {
	if addr == nil {
		return errInvalidAddress
	}
	if _, err := w.Write(addr); err != nil {
		return err
	}
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], id)
	_, err := w.Write(buf[:])
	return err
}

func ReadUDPControl(r io.Reader) (socks5.Addr, uint16, error) {
	addr, err := socks5.ReadAddr0(r)
	if err != nil {
		return nil, 0, err
	}
	id, err := ReadUint16(r)
	if err != nil {
		return nil, 0, err
	}
	return addr, id, nil
}

func EncodeDatagram(id uint16, payload []byte) ([]byte, error) {
	if len(payload) > maxUDPPacketSize {
		return nil, errPacketTooLarge
	}
	packet := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(packet[:2], id)
	copy(packet[2:], payload)
	return packet, nil
}

func DecodeDatagram(packet []byte) (uint16, []byte, error) {
	if len(packet) < 2 {
		return 0, nil, errInvalidDatagram
	}
	return binary.BigEndian.Uint16(packet[:2]), packet[2:], nil
}

func WritePacketStreamHeader(w io.Writer, id uint16) error {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], id)
	_, err := w.Write(buf[:])
	return err
}

func WritePacketStreamPayload(w io.Writer, payload []byte) error {
	if len(payload) > maxUDPPacketSize {
		return errPacketTooLarge
	}
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], uint16(len(payload)))
	if _, err := w.Write(buf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func ReadUint16(r io.Reader) (uint16, error) {
	var buf [2]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(buf[:]), nil
}
