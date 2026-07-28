package sniffer

import (
	"bytes"
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
	// Timeout before quic sniffer all packets
	quicWaitConn = time.Second * 3

	// maxCryptoStreamOffset is the maximum offset allowed on any of the crypto streams.
	// This limits the size of the ClientHello and Certificates that can be received.
	maxCryptoStreamOffset = 16 * (1 << 10)
)

// RFC 9000 §19
const (
	framePadding         byte = 0x0
	framePing            byte = 0x1
	frameAck             byte = 0x2
	frameAckWithECN      byte = 0x3
	frameCrypto          byte = 0x6
	frameConnectionClose byte = 0x1c
)

var (
	errNotQUIC        = errors.New("not QUIC")
	errNotQUICInitial = errors.New("not QUIC initial packet")
)

type quicStructure struct {
	ver         uint32
	typeInitial byte
	initialSalt []byte
	labelPrefix string
}

var (
	quicDraft29 = quicStructure{
		ver:         0xff00001d,
		typeInitial: 0b00,
		initialSalt: []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99},
		labelPrefix: "quic",
	}
	quicV1 = quicStructure{ // RFC 9001 §5.2
		ver:         0x1,
		typeInitial: 0b00,
		initialSalt: []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a},
		labelPrefix: "quic",
	}
	quicV2 = quicStructure{ // RFC 9369 §3.2 – 3.3
		ver:         0x6b3343cf,
		typeInitial: 0b01,
		initialSalt: []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9},
		labelPrefix: "quicv2",
	}

	listQUICVersions = []*quicStructure{&quicDraft29, &quicV1, &quicV2}
)

type quicLabels struct {
	hp  []byte
	key []byte
	iv  []byte
}

var _ sniffer.Sniffer = (*QUICSniffer)(nil)
var _ sniffer.MultiPacketSniffer = (*QUICSniffer)(nil)

type QUICSniffer struct {
	*BaseSniffer
}

func NewQUICSniffer(snifferConfig SnifferConfig) (*QUICSniffer, error) {
	ports := snifferConfig.Ports
	if len(ports) == 0 {
		ports = utils.IntRanges[uint16]{utils.NewRange[uint16](443, 443)}
	}
	return &QUICSniffer{
		BaseSniffer: NewBaseSniffer(ports, C.UDP),
	}, nil
}

func (sniffer *QUICSniffer) Protocol() string {
	return "quic"
}

func (sniffer *QUICSniffer) SupportNetwork() C.NetWork {
	return C.UDP
}

func (sniffer *QUICSniffer) SniffData(b []byte) (string, error) {
	return "", ErrorUnsupportedSniffer
}

func (sniffer *QUICSniffer) WrapperSender(packetSender constant.PacketSender, replaceDomain sniffer.ReplaceDomain) constant.PacketSender {
	return &quicPacketSender{
		PacketSender:  packetSender,
		replaceDomain: replaceDomain,
		done:          make(chan struct{}),
	}
}

var _ constant.PacketSender = (*quicPacketSender)(nil)

type quicPacketSender struct {
	structure *quicStructure
	lock      sync.RWMutex
	ranges    utils.IntRanges[uint64]
	buffer    []byte
	result    string

	replaceDomain sniffer.ReplaceDomain

	constant.PacketSender

	labelsOnce sync.Once
	labels     quicLabels

	done chan struct{}

	closed    bool
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

	err := q.readQUICData(current.Data())
	if err != nil {
		q.close()
		return
	}
}

// DoSniff wait sniffer recv all fragments and update the domain
func (q *quicPacketSender) DoSniff(metadata *constant.Metadata) error {
	select {
	case <-q.done:
		q.lock.RLock()
		if r := q.result; r != "" {
			q.replaceDomain(metadata, r)
		}
		q.lock.RUnlock()
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
	defer q.lock.Unlock()
	if !q.closed {
		close(q.done)
		q.closed = true
		if q.buffer != nil {
			_ = pool.Put(q.buffer)
			q.buffer = nil
		}
		q.ranges = nil
	}
}

func (q *quicPacketSender) readQUICData(b []byte) error {
	buffer := buf.As(b)

	typeByte, err := buffer.ReadByte()
	if err != nil {
		return errNotQUIC
	}

	isLongHeader := typeByte&0x80 > 0
	if !isLongHeader || typeByte&0x40 == 0 {
		return errNotQUICInitial
	}

	vb, err := buffer.ReadBytes(4)
	if err != nil {
		return errNotQUIC
	}

	s, err := q.getQUICStructure(vb)
	if err != nil {
		return err
	}

	connIDLen, err := buffer.ReadByte()
	if err != nil || connIDLen == 0 {
		return errNotQUIC
	}

	destConnID := make([]byte, int(connIDLen))
	if _, err := io.ReadFull(buffer, destConnID); err != nil {
		return errNotQUIC
	}

	packetType := (typeByte & 0x30) >> 4
	if packetType != s.typeInitial {
		return nil
	}

	if l, err := buffer.ReadByte(); err != nil {
		return errNotQUIC
	} else if _, err := buffer.ReadBytes(int(l)); err != nil {
		return errNotQUIC
	}

	tokenLen, err := quicvarint.Read(buffer)
	if err != nil || tokenLen > uint64(len(b)) {
		return errNotQUIC
	}

	if _, err = buffer.ReadBytes(int(tokenLen)); err != nil {
		return errNotQUIC
	}

	packetLen, err := quicvarint.Read(buffer)
	if err != nil {
		return errNotQUIC
	}

	hdrLen := len(b) - buffer.Len()

	labels := q.expandLabels(destConnID, s)

	block, err := aes.NewCipher(labels.hp)
	if err != nil {
		return err
	}

	cache := buf.NewPacket()
	defer cache.Release()

	if hdrLen+4+16 > len(b) {
		return errNotQUIC
	}

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
		return errNotQUIC
	}

	data := b[extHdrLen : int(packetLen)+hdrLen]

	aesCipher, err := aes.NewCipher(labels.key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return err
	}

	// We only decrypt once, so we do not need to XOR it back.
	// https://github.com/quic-go/qtls-go1-20/blob/e132a0e6cb45e20ac0b705454849a11d09ba5a54/cipher_suites.go#L496
	iv := bytes.Clone(labels.iv)
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

		frameType := framePadding
		for frameType == framePadding && !buffer.IsEmpty() {
			frameType, _ = buffer.ReadByte()
		}
		switch frameType {
		case framePadding:
		case framePing:
		case frameAck, frameAckWithECN:
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
			if frameType == frameAckWithECN {
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
		case frameCrypto:
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
		case frameConnectionClose:
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
			return errNotQUICInitial
		}
	}

	domain, err := q.tryAssemble()
	if err != nil {
		return err
	}
	if domain != "" {
		q.lock.Lock()
		q.result = domain
		q.lock.Unlock()
		q.close()
	}

	return nil
}

func (q *quicPacketSender) tryAssemble() (string, error) {
	q.lock.RLock()
	defer q.lock.RUnlock()

	if q.closed {
		// close() was called, just return
		return "", nil
	}

	if len(q.ranges) != 1 || q.ranges[0].Start() != 0 || q.ranges[0].End() != uint64(len(q.buffer)) {
		// incomplete fragment, just return
		return "", nil
	}

	if len(q.buffer) <= 4 ||
		// Handshake Type (1) + uint24 Length (3) + ClientHello body
		// maxCryptoStreamOffset is in the valid range of uint16 so just ignore the q.buffer[1]
		int(binary.BigEndian.Uint16([]byte{q.buffer[2], q.buffer[3]})+4) != len(q.buffer) {
		// end of segment not reached, just return
		return "", nil
	}

	domain, err := ReadClientHello(q.buffer)
	if err != nil {
		return "", err
	}

	return *domain, nil
}

func (q *quicPacketSender) getQUICStructure(vb []byte) (*quicStructure, error) {
	q.lock.Lock()
	defer q.lock.Unlock()

	if q.structure != nil {
		return q.structure, nil
	}

	n := binary.BigEndian.Uint32(vb)
	for _, v := range listQUICVersions {
		if v.ver == n {
			q.structure = v
			return q.structure, nil
		}
	}

	return nil, errNotQUIC
}

func (q *quicPacketSender) expandLabels(destConnID []byte, s *quicStructure) quicLabels {
	q.labelsOnce.Do(func() {
		initialSecret := hkdf.Extract(crypto.SHA256.New, destConnID, s.initialSalt)
		secret := hkdfExpandLabel(initialSecret, "client in", crypto.SHA256.Size())

		lp := s.labelPrefix

		q.labels = quicLabels{
			hp:  hkdfExpandLabel(secret, lp+" hp", 16),
			key: hkdfExpandLabel(secret, lp+" key", 16),
			iv:  hkdfExpandLabel(secret, lp+" iv", 12),
		}
	})
	return q.labels
}

func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	b := make([]byte, 0, 2+1+6+len(label)+1)
	b = binary.BigEndian.AppendUint16(b, uint16(length))
	b = append(b, byte(6+len(label)))
	b = append(b, "tls13 "...)
	b = append(b, label...)
	b = append(b, 0) // context

	out := make([]byte, length)
	n, err := hkdf.Expand(crypto.SHA256.New, secret, b).Read(out)
	if err != nil || n != length {
		panic("quic: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}
