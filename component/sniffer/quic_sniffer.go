package sniffer

import (
	"crypto"
	"encoding/binary"
	"errors"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/constant"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/sniffer"
	"golang.org/x/crypto/hkdf"
)

// Modified from https://github.com/v2fly/v2ray-core/blob/master/common/protocol/quic/sniff.go

const (
	versionDraft29 uint32 = 0xff00001d
	version1       uint32 = 0x1
	// Timeout before quic sniffer all packets
	quicWaitConn          = time.Second * 3
	quicPacketTypeInitial = 0x00
	quicPacketType0RTT    = 0x01
)

var (
	quicSaltOld       = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
	quicSalt          = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	errNotQuic        = errors.New("not QUIC")
	errNotQuicInitial = errors.New("not QUIC initial packet")
)

var _ sniffer.Sniffer = (*QuicSniffer)(nil)
var _ sniffer.MultiPacketSniffer = (*QuicSniffer)(nil)

type QuicSniffer struct {
	*BaseSniffer
}

func NewQuicSniffer(snifferConfig SnifferConfig) (*QuicSniffer, error) {
	ports := snifferConfig.Ports
	if len(ports) == 0 {
		ports = utils.IntRanges[uint16]{utils.NewRange[uint16](443, 443)}
	}
	return &QuicSniffer{
		BaseSniffer: NewBaseSniffer(ports, C.UDP),
	}, nil
}

func (sniffer *QuicSniffer) Protocol() string {
	return "quic"
}

func (sniffer *QuicSniffer) SupportNetwork() C.NetWork {
	return C.UDP
}

func (sniffer *QuicSniffer) WrapperSender(packetSender constant.PacketSender, override bool) constant.PacketSender {
	return &quicConnection{
		sender:   packetSender,
		buffer:   make([]quicDataBlock, 0),
		chClose:  make(chan struct{}),
		override: override,
	}
}

func (sniffer *QuicSniffer) SniffData(b []byte) (string, error) {
	return "", ErrorUnsupportedSniffer
}

func hkdfExpandLabel(hash crypto.Hash, secret, context []byte, label string, length int) []byte {
	b := make([]byte, 3, 3+6+len(label)+1+len(context))
	binary.BigEndian.PutUint16(b, uint16(length))
	b[2] = uint8(6 + len(label))
	b = append(b, []byte("tls13 ")...)
	b = append(b, []byte(label)...)
	b = b[:3+6+len(label)+1]
	b[3+6+len(label)] = uint8(len(context))
	b = append(b, context...)

	out := make([]byte, length)
	n, err := hkdf.Expand(hash.New, secret, b).Read(out)
	if err != nil || n != length {
		panic("quic: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}
