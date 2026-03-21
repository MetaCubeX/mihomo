package sniffer

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/constant"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/sniffer"

	"github.com/metacubex/quic-go/quicvarint"
	"golang.org/x/crypto/hkdf"
)

// Modified from https://github.com/v2fly/v2ray-core/blob/master/common/protocol/quic/sniff.go

const (
	versionDraft29 uint32 = 0xff00001d
	version1       uint32 = 0x1

	quicPacketTypeInitial = 0x00
	quicPacketType0RTT    = 0x01

	// Timeout before quic sniffer all packets
	quicWaitConn = time.Second * 3

	// maxCryptoStreamOffset is the maximum offset allowed on any of the crypto streams.
	// This limits the size of the ClientHello and Certificates that can be received.
	maxCryptoStreamOffset = 16 * (1 << 10)
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

func (sniffer *QuicSniffer) SniffData(b []byte) (string, error) {
	return "", ErrorUnsupportedSniffer
}

func (sniffer *QuicSniffer) WrapperSender(packetSender constant.PacketSender, replaceDomain sniffer.ReplaceDomain) constant.PacketSender {
	return &quicPacketSender{
		PacketSender:  packetSender,
		replaceDomain: replaceDomain,
		chClose:       make(chan struct{}),
	}
}

var _ constant.PacketSender = (*quicPacketSender)(nil)

type quicPacketSender struct {
	lock   sync.RWMutex
	ranges utils.IntRanges[uint64]
	buffer []byte
	result *string

	replaceDomain sniffer.ReplaceDomain

	constant.PacketSender

	chClose chan struct{}
	closed  bool
}

// Send will send PacketAdapter nonblocking
// the implement must call UDPPacket.Drop() inside Send
func (q *quicPacketSender) Send(current constant.PacketAdapter) {
	defer q.PacketSender.Send(current)

	q.lock.RLock()
	if q.closed {
		q.lock.RUnlock()
		return
	}
	q.lock.RUnlock()

	err := q.readQuicData(current.Data())
	if err != nil {
		q.close()
		return
	}
}

// DoSniff wait sniffer recv all fragments and update the domain
func (q *quicPacketSender) DoSniff(metadata *constant.Metadata) error {
	select {
	case <-q.chClose:
		q.lock.RLock()
		if q.result != nil {
			host := *q.result
			q.replaceDomain(metadata, host)
		}
		q.lock.RUnlock()
		break
	case <-time.After(quicWaitConn):
		q.close()
	}

	return q.PacketSender.DoSniff(metadata)
}

// Close stop the Process loop
func (q *quicPacketSender) Close() {
	q.PacketSender.Close()
	q.close()
}

func (q *quicPacketSender) close() {
	q.lock.Lock()
	q.closeLocked()
	q.lock.Unlock()
}

func (q *quicPacketSender) closeLocked() {
	if !q.closed {
		close(q.chClose)
		q.closed = true
		if q.buffer != nil {
			_ = pool.Put(q.buffer)
			q.buffer = nil
		}
		q.ranges = nil
	}
}

func (q *quicPacketSender) readQuicData(b []byte) error {
	buffer := buf.As(b)
	typeByte, err := buffer.ReadByte()
	if err != nil {
		return errNotQuic
	}
	isLongHeader := typeByte&0x80 > 0
	if !isLongHeader || typeByte&0x40 == 0 {
		return errNotQuicInitial
	}

	vb, err := buffer.ReadBytes(4)
	if err != nil {
		return errNotQuic
	}

	versionNumber := binary.BigEndian.Uint32(vb)

	if versionNumber != 0 && typeByte&0x40 == 0 {
		return errNotQuic
	} else if versionNumber != versionDraft29 && versionNumber != version1 {
		return errNotQuic
	}

	connIdLen, err := buffer.ReadByte()
	if err != nil || connIdLen == 0 {
		return errNotQuic
	}
	destConnID := make([]byte, int(connIdLen))
	if _, err := io.ReadFull(buffer, destConnID); err != nil {
		return errNotQuic
	}

	packetType := (typeByte & 0x30) >> 4
	if packetType != quicPacketTypeInitial {
		return nil
	}

	if l, err := buffer.ReadByte(); err != nil {
		return errNotQuic
	} else if _, err := buffer.ReadBytes(int(l)); err != nil {
		return errNotQuic
	}

	tokenLen, err := quicvarint.Read(buffer)
	if err != nil || tokenLen > uint64(len(b)) {
		return errNotQuic
	}

	if _, err = buffer.ReadBytes(int(tokenLen)); err != nil {
		return errNotQuic
	}

	packetLen, err := quicvarint.Read(buffer)
	if err != nil {
		return errNotQuic
	}

	hdrLen := len(b) - buffer.Len()

	var salt []byte
	if versionNumber == version1 {
		salt = quicSalt
	} else {
		salt = quicSaltOld
	}
	initialSecret := hkdf.Extract(crypto.SHA256.New, destConnID, salt)
	secret := hkdfExpandLabel(crypto.SHA256, initialSecret, []byte{}, "client in", crypto.SHA256.Size())
	hpKey := hkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic hp", 16)
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return err
	}

	cache := buf.NewPacket()
	defer cache.Release()

	mask := cache.Extend(block.BlockSize())
	block.Encrypt(mask, b[hdrLen+4:hdrLen+4+16])
	firstByte := b[0]
	// Encrypt/decrypt first byte.

	if isLongHeader {
		// Long header: 4 bits masked
		// High 4 bits are not protected.
		firstByte ^= mask[0] & 0x0f
	} else {
		// Short header: 5 bits masked
		// High 3 bits are not protected.
		firstByte ^= mask[0] & 0x1f
	}
	packetNumberLength := int(firstByte&0x3 + 1) // max = 4 (64-bit sequence number)
	extHdrLen := hdrLen + packetNumberLength

	// copy to avoid modify origin data
	extHdr := cache.Extend(extHdrLen)
	copy(extHdr, b)
	extHdr[0] = firstByte

	packetNumber := extHdr[hdrLen:extHdrLen]
	// Encrypt/decrypt packet number.
	for i := range packetNumber {
		packetNumber[i] ^= mask[1+i]
	}

	if int(packetLen)+hdrLen > len(b) || extHdrLen > len(b) {
		return errNotQuic
	}

	data := b[extHdrLen : int(packetLen)+hdrLen]

	key := hkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic key", 16)
	iv := hkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic iv", 12)
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return err
	}

	// We only decrypt once, so we do not need to XOR it back.
	// https://github.com/quic-go/qtls-go1-20/blob/e132a0e6cb45e20ac0b705454849a11d09ba5a54/cipher_suites.go#L496
	for i, b := range packetNumber {
		iv[len(iv)-len(packetNumber)+i] ^= b
	}
	dst := cache.Extend(len(data))
	decrypted, err := aead.Open(dst[:0], iv, data, extHdr)
	if err != nil {
		return err
	}

	buffer = buf.As(decrypted)

	for i := 0; !buffer.IsEmpty(); i++ {
		q.lock.RLock()
		if q.closed {
			q.lock.RUnlock()
			// close() was called, just return
			return nil
		}
		q.lock.RUnlock()

		frameType := byte(0x0) // Default to PADDING frame
		for frameType == 0x0 && !buffer.IsEmpty() {
			frameType, _ = buffer.ReadByte()
		}
		switch frameType {
		case 0x00: // PADDING frame
		case 0x01: // PING frame
		case 0x02, 0x03: // ACK frame
			if _, err = quicvarint.Read(buffer); err != nil { // Field: Largest Acknowledged
				return io.ErrUnexpectedEOF
			}
			if _, err = quicvarint.Read(buffer); err != nil { // Field: ACK Delay
				return io.ErrUnexpectedEOF
			}
			ackRangeCount, err := quicvarint.Read(buffer) // Field: ACK Range Count
			if err != nil {
				return io.ErrUnexpectedEOF
			}
			if _, err = quicvarint.Read(buffer); err != nil { // Field: First ACK Range
				return io.ErrUnexpectedEOF
			}
			for i := 0; i < int(ackRangeCount); i++ { // Field: ACK Range
				if _, err = quicvarint.Read(buffer); err != nil { // Field: ACK Range -> Gap
					return io.ErrUnexpectedEOF
				}
				if _, err = quicvarint.Read(buffer); err != nil { // Field: ACK Range -> ACK Range Length
					return io.ErrUnexpectedEOF
				}
			}
			if frameType == 0x03 {
				if _, err = quicvarint.Read(buffer); err != nil { // Field: ECN Counts -> ECT0 Count
					return io.ErrUnexpectedEOF
				}
				if _, err = quicvarint.Read(buffer); err != nil { // Field: ECN Counts -> ECT1 Count
					return io.ErrUnexpectedEOF
				}
				if _, err = quicvarint.Read(buffer); err != nil { //nolint:misspell // Field: ECN Counts -> ECT-CE Count
					return io.ErrUnexpectedEOF
				}
			}
		case 0x06: // CRYPTO frame, we will use this frame
			offset, err := quicvarint.Read(buffer) // Field: Offset
			if err != nil {
				return io.ErrUnexpectedEOF
			}
			length, err := quicvarint.Read(buffer) // Field: Length
			if err != nil || length > uint64(buffer.Len()) {
				return io.ErrUnexpectedEOF
			}

			end := offset + length
			if end > maxCryptoStreamOffset {
				return io.ErrShortBuffer
			}

			q.lock.Lock()
			if q.closed {
				q.lock.Unlock()
				// close() was called, just return
				return nil
			}
			if q.buffer == nil {
				q.buffer = pool.Get(maxCryptoStreamOffset)[:end]
			} else if end > uint64(len(q.buffer)) {
				q.buffer = q.buffer[:end]
			}
			target := q.buffer[offset:end]
			if _, err := buffer.Read(target); err != nil { // Field: Crypto Data
				q.lock.Unlock()
				return io.ErrUnexpectedEOF
			}
			q.ranges = append(q.ranges, utils.NewRange(offset, end))
			q.ranges = q.ranges.Merge()
			q.lock.Unlock()
		case 0x1c: // CONNECTION_CLOSE frame, only 0x1c is permitted in initial packet
			if _, err = quicvarint.Read(buffer); err != nil { // Field: Error Code
				return io.ErrUnexpectedEOF
			}
			if _, err = quicvarint.Read(buffer); err != nil { // Field: Frame Type
				return io.ErrUnexpectedEOF
			}
			length, err := quicvarint.Read(buffer) // Field: Reason Phrase Length
			if err != nil {
				return io.ErrUnexpectedEOF
			}
			if _, err := buffer.ReadBytes(int(length)); err != nil { // Field: Reason Phrase
				return io.ErrUnexpectedEOF
			}
		default:
			// Only above frame types are permitted in initial packet.
			// See https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.2-8
			return errNotQuicInitial
		}
	}

	return q.tryAssemble()
}

func (q *quicPacketSender) tryAssemble() error {
	q.lock.RLock()

	if q.closed {
		q.lock.RUnlock()
		// close() was called, just return
		return nil
	}

	if len(q.ranges) != 1 || q.ranges[0].Start() != 0 || q.ranges[0].End() != uint64(len(q.buffer)) {
		q.lock.RUnlock()
		// incomplete fragment, just return
		return nil
	}

	if len(q.buffer) <= 4 ||
		// Handshake Type (1) + uint24 Length (3) + ClientHello body
		// maxCryptoStreamOffset is in the valid range of uint16 so just ignore the q.buffer[1]
		int(binary.BigEndian.Uint16([]byte{q.buffer[2], q.buffer[3]})+4) != len(q.buffer) {
		q.lock.RUnlock()
		// end of segment not reached, just return
		return nil
	}

	domain, err := ReadClientHello(q.buffer)
	q.lock.RUnlock()
	if err != nil {
		return err
	}

	q.lock.Lock()
	q.result = domain
	q.closeLocked()
	q.lock.Unlock()

	return nil
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
