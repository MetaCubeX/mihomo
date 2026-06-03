package mkcp

import (
	"encoding/binary"
	"fmt"

	"github.com/metacubex/randv2"
)

// PacketHeader masquerades each UDP datagram with a fake protocol header.
// Only Size and Serialize are needed on the client side; the reader merely
// strips Size() bytes from incoming packets without validating them, matching
// xray-core's internet.PacketHeader.
type PacketHeader interface {
	Size() int32
	Serialize([]byte)
}

func rollUint16() uint16 {
	return uint16(randv2.Uint32())
}

// NewPacketHeader builds a header masquerade by its mKCP header.type name.
// An empty name or "none" yields a nil header (no masquerade), which is
// equivalent on the wire to a zero-size header.
func NewPacketHeader(name string) (PacketHeader, error) {
	switch name {
	case "", "none", "noop":
		return nil, nil
	case "srtp":
		return &srtpHeader{header: 0xB5E8, number: rollUint16()}, nil
	case "utp":
		return &utpHeader{header: 1, extension: 0, connectionID: rollUint16()}, nil
	case "wechat-video", "wechat":
		return &wechatVideoHeader{sn: uint32(rollUint16())}, nil
	case "wireguard":
		return &wireguardHeader{}, nil
	default:
		return nil, fmt.Errorf("unknown mkcp header type: %s", name)
	}
}

// srtpHeader masquerades as SRTP traffic. (4 bytes)
type srtpHeader struct {
	header uint16
	number uint16
}

func (*srtpHeader) Size() int32 { return 4 }

func (h *srtpHeader) Serialize(b []byte) {
	h.number++
	binary.BigEndian.PutUint16(b, h.header)
	binary.BigEndian.PutUint16(b[2:], h.number)
}

// utpHeader masquerades as uTP (BitTorrent) traffic. (4 bytes)
type utpHeader struct {
	header       byte
	extension    byte
	connectionID uint16
}

func (*utpHeader) Size() int32 { return 4 }

func (h *utpHeader) Serialize(b []byte) {
	binary.BigEndian.PutUint16(b, h.connectionID)
	b[2] = h.header
	b[3] = h.extension
}

// wechatVideoHeader masquerades as WeChat video call traffic. (13 bytes)
type wechatVideoHeader struct {
	sn uint32
}

func (*wechatVideoHeader) Size() int32 { return 13 }

func (h *wechatVideoHeader) Serialize(b []byte) {
	h.sn++
	b[0] = 0xa1
	b[1] = 0x08
	binary.BigEndian.PutUint32(b[2:], h.sn) // b[2:6]
	b[6] = 0x00
	b[7] = 0x10
	b[8] = 0x11
	b[9] = 0x18
	b[10] = 0x30
	b[11] = 0x22
	b[12] = 0x30
}

// wireguardHeader masquerades as WireGuard traffic. (4 bytes)
type wireguardHeader struct{}

func (wireguardHeader) Size() int32 { return 4 }

func (wireguardHeader) Serialize(b []byte) {
	b[0] = 0x04
	b[1] = 0x00
	b[2] = 0x00
	b[3] = 0x00
}
