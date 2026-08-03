package sniffer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/sniffer"
)

var errNotBitTorrent = errors.New("not BitTorrent")

const (
	// btHandshakeHeader is the fixed prefix of the BitTorrent handshake message,
	// a length byte followed by the protocol identifier. See
	// https://www.bittorrent.org/beps/bep_0003.html
	btHandshakeHeader = "\x13BitTorrent protocol"

	// magic constants of the UDP tracker protocol
	// https://www.bittorrent.org/beps/bep_0015.html
	trackerProtocolID     = 0x41727101980
	trackerActionConnect  = 0
	trackerConnectMinSize = 16
)

var _ sniffer.ProtocolSniffer = (*BitTorrentSniffer)(nil)

type BitTorrentSniffer struct {
	*BaseSniffer
}

func NewBitTorrentSniffer(snifferConfig SnifferConfig) (*BitTorrentSniffer, error) {
	ports := snifferConfig.Ports
	if len(ports) == 0 {
		// BitTorrent peers listen on arbitrary ports, so there is no sensible
		// port whitelist to default to
		ports = utils.IntRanges[uint16]{utils.NewRange[uint16](1, 65535)}
	}
	return &BitTorrentSniffer{
		BaseSniffer: NewBaseSniffer(ports, C.ALLNet),
	}, nil
}

func (bt *BitTorrentSniffer) Protocol() string {
	return "bittorrent"
}

func (bt *BitTorrentSniffer) SupportNetwork() C.NetWork {
	return C.ALLNet
}

// SniffData implements sniffer.Sniffer. BitTorrent traffic carries no domain,
// so this sniffer is only usable through SniffProtocol.
func (bt *BitTorrentSniffer) SniffData(bytes []byte) (string, error) {
	return "", errNotBitTorrent
}

func (bt *BitTorrentSniffer) SniffProtocol(network C.NetWork, b []byte) (string, error) {
	switch network {
	case C.TCP:
		if err := SniffBitTorrentHandshake(b); err != nil {
			return "", err
		}
	case C.UDP:
		if SniffUTP(b) != nil && SniffUDPTracker(b) != nil {
			return "", errNotBitTorrent
		}
	default:
		return "", errNotBitTorrent
	}
	return C.ProtocolBitTorrent, nil
}

// SniffBitTorrentHandshake detects the handshake that opens every BitTorrent
// peer connection. See https://www.bittorrent.org/beps/bep_0003.html
func SniffBitTorrentHandshake(b []byte) error {
	if len(b) < len(btHandshakeHeader) {
		// only ask for more data while what arrived so far still matches,
		// otherwise this is definitely something else
		if !strings.HasPrefix(btHandshakeHeader, string(b)) {
			return errNotBitTorrent
		}
		return &errNeedAtLeastData{
			length: len(btHandshakeHeader),
			err:    ErrNoClue,
		}
	}

	if string(b[:len(btHandshakeHeader)]) != btHandshakeHeader {
		return errNotBitTorrent
	}
	return nil
}

// SniffUTP detects a uTP packet, the transport BitTorrent peers use over UDP.
// See https://www.bittorrent.org/beps/bep_0029.html and
// https://github.com/bittorrent/libutp/blob/2b364cbb0650bdab64a5de2abb4518f9f228ec44/utp_internal.cpp#L112
func SniffUTP(b []byte) error {
	// a valid uTP packet is at least a full 20 bytes header
	if len(b) < 20 {
		return errNotBitTorrent
	}

	version := b[0] & 0x0F
	ty := b[0] >> 4
	if version != 1 || ty > 4 {
		return errNotBitTorrent
	}

	// walk the extension chain, every link is a type byte, a length byte and
	// that many bytes of payload, terminated by a zero type
	extension := b[1]
	reader := bytes.NewReader(b[20:])
	for extension != 0 {
		if err := binary.Read(reader, binary.BigEndian, &extension); err != nil {
			return errNotBitTorrent
		}
		if extension > 0x04 {
			return errNotBitTorrent
		}
		var length byte
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			return errNotBitTorrent
		}
		// bytes.Reader happily seeks past the end, so check the chain stays
		// inside the packet instead of accepting a truncated one
		if int64(length) > int64(reader.Len()) {
			return errNotBitTorrent
		}
		if _, err := reader.Seek(int64(length), io.SeekCurrent); err != nil {
			return errNotBitTorrent
		}
	}

	return nil
}

// SniffUDPTracker detects the connect request of the UDP tracker protocol.
// See https://www.bittorrent.org/beps/bep_0015.html
func SniffUDPTracker(b []byte) error {
	if len(b) < trackerConnectMinSize {
		return errNotBitTorrent
	}
	if binary.BigEndian.Uint64(b[:8]) != trackerProtocolID {
		return errNotBitTorrent
	}
	if binary.BigEndian.Uint32(b[8:12]) != trackerActionConnect {
		return errNotBitTorrent
	}
	return nil
}
