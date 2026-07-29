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

	// maxCryptoStreamOffset bounds both the highest Initial CRYPTO stream offset
	// and the payload retained by the sniffer. Its coverage bitmap uses at most
	// another 8 KiB. The 64 KiB payload budget matches TCP sniffing and the
	// largest pooled buffer, and aligns with the Initial CRYPTO limits used by
	// ngtcp2 and Cloudflare quiche while remaining more permissive than the
	// 16 KiB limits in quic-go and BoringSSL.
	// This is a resource policy, not a QUIC or TLS protocol limit. For example,
	// rustls permits a 65,535-byte Handshake payload plus its four-byte header;
	// covering that boundary case would exceed the shared 64 KiB sniffing budget.
	maxCryptoStreamOffset = 64 * (1 << 10)
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
	errNotQUIC              = errors.New("not QUIC")
	errNotQUICInitial       = errors.New("not QUIC initial packet")
	errQUICDecryptionFailed = errors.New("QUIC decryption failed")
)

// QUIC v2 remaps long-header packet type bits, so Initial and Retry values are
// stored with the other version-specific parameters.
type quicStructure struct {
	ver         uint32
	typeInitial byte
	typeRetry   byte
	initialSalt []byte
	labelPrefix string
}

var (
	quicDraft29 = quicStructure{
		ver:         0xff00001d,
		typeInitial: 0b00,
		typeRetry:   0b11,
		initialSalt: []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99},
		labelPrefix: "quic",
	}
	quicV1 = quicStructure{ // RFC 9001 §5.2
		ver:         0x1,
		typeInitial: 0b00,
		typeRetry:   0b11,
		initialSalt: []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a},
		labelPrefix: "quic",
	}
	quicV2 = quicStructure{ // RFC 9369 §3.2 – 3.3
		ver:         0x6b3343cf,
		typeInitial: 0b01,
		typeRetry:   0b00,
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

type quicInitialKey struct {
	destConnID          []byte
	labels              quicLabels
	largestPacketNumber int64
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
	structure           *quicStructure
	lock                sync.RWMutex
	initialKeys         []quicInitialKey
	buffer              []byte
	receivedCryptoData  bitmap
	contiguousCryptoEnd uint64
	result              string

	replaceDomain sniffer.ReplaceDomain

	constant.PacketSender

	done chan struct{}

	closed bool
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
		q.receivedCryptoData = bitmap{}
		q.contiguousCryptoEnd = 0
	}
}

func (q *quicPacketSender) readQUICData(b []byte) error {
	// A UDP datagram can contain multiple coalesced QUIC packets. Walk each
	// packet boundary so every Initial packet contributes its CRYPTO data.
	firstPacket := true
	for len(b) > 0 {
		packetLen, err := q.readQUICPacket(b, !firstPacket)
		if err != nil {
			return err
		}
		if packetLen <= 0 || packetLen > len(b) {
			return errNotQUIC
		}
		b = b[packetLen:]
		firstPacket = false
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

// readQUICPacket processes one packet and returns its length in the datagram.
// Long-header packets carry an explicit length. A short-header packet is
// accepted only after one of them and consumes the remainder because it has
// no length field.
func (q *quicPacketSender) readQUICPacket(b []byte, coalesced bool) (int, error) {
	buffer := buf.As(b)

	typeByte, err := buffer.ReadByte()
	if err != nil {
		return 0, errNotQUIC
	}

	if typeByte&0x80 == 0 {
		if coalesced {
			return len(b), nil
		}
		return 0, errNotQUICInitial
	}
	if typeByte&0x40 == 0 {
		return 0, errNotQUICInitial
	}

	vb, err := buffer.ReadBytes(4)
	if err != nil {
		return 0, errNotQUIC
	}

	s, err := q.getQUICStructure(vb)
	if err != nil {
		return 0, err
	}

	connIDLen, err := buffer.ReadByte()
	if err != nil || connIDLen == 0 {
		return 0, errNotQUIC
	}

	destConnID := make([]byte, int(connIDLen))
	if _, err := io.ReadFull(buffer, destConnID); err != nil {
		return 0, errNotQUIC
	}

	if l, err := buffer.ReadByte(); err != nil {
		return 0, errNotQUIC
	} else if _, err := buffer.ReadBytes(int(l)); err != nil {
		return 0, errNotQUIC
	}

	packetType := (typeByte & 0x30) >> 4
	if packetType == s.typeRetry {
		// Retry has no Length field and therefore consumes the rest of the datagram.
		return len(b), nil
	}

	if packetType == s.typeInitial {
		tokenLen, err := quicvarint.Read(buffer)
		if err != nil || tokenLen > uint64(buffer.Len()) {
			return 0, errNotQUIC
		}

		if _, err = buffer.ReadBytes(int(tokenLen)); err != nil {
			return 0, errNotQUIC
		}
	}

	packetLen, err := quicvarint.Read(buffer)
	if err != nil {
		return 0, errNotQUIC
	}

	hdrLen := len(b) - buffer.Len()
	if packetLen > uint64(len(b)-hdrLen) {
		return 0, errNotQUIC
	}
	packetEnd := hdrLen + int(packetLen)
	if packetType != s.typeInitial {
		// Skip coalesced 0-RTT and Handshake packets at their declared boundary.
		return packetEnd, nil
	}

	cache := buf.NewPacket()
	defer cache.Release()

	decrypted, err := q.decryptQUICInitialPacket(b, hdrLen, packetEnd, destConnID, s, cache)
	if err != nil {
		if errors.Is(err, errQUICDecryptionFailed) {
			// Authentication failure can result from corruption or a delayed
			// packet outside the reconstruction window. Ignore this Initial and
			// continue sniffing subsequent packets in the datagram or connection.
			return packetEnd, nil
		}
		return 0, err
	}

	if err := q.readQUICFrames(decrypted); err != nil {
		return 0, err
	}

	return packetEnd, nil
}

// decryptQUICInitialPacket tries the Initial key epochs retained for the
// connection. Retry changes the Initial keys without resetting packet numbers.
// Per-key decoder state also lets delayed pre-Retry packets be authenticated,
// while later header DCID changes continue using the same retained keys.
func (q *quicPacketSender) decryptQUICInitialPacket(b []byte, hdrLen, packetEnd int, destConnID []byte, s *quicStructure, cache *buf.Buffer) ([]byte, error) {
	q.lock.Lock()
	defer q.lock.Unlock()

	if len(q.initialKeys) == 0 {
		q.initialKeys = append(q.initialKeys, newQUICInitialKey(destConnID, s))
	}

	var decryptErr error
	hasCurrentDestConnID := false
	largestPacketNumber := int64(-1)
	for i := range q.initialKeys {
		key := &q.initialKeys[i]
		hasCurrentDestConnID = hasCurrentDestConnID || bytes.Equal(destConnID, key.destConnID)
		if key.largestPacketNumber > largestPacketNumber {
			largestPacketNumber = key.largestPacketNumber
		}
		decrypted, packetNumber, err := decryptQUICInitialPacket(b, hdrLen, packetEnd, key.labels, key.largestPacketNumber, cache)
		if err == nil {
			if packetNumber > key.largestPacketNumber {
				key.largestPacketNumber = packetNumber
			}
			return decrypted, nil
		}
		decryptErr = err
	}
	if hasCurrentDestConnID {
		// These keys were already derived from the current DCID. A later epoch
		// was still tried above because its keys may outlive a header DCID change.
		return nil, decryptErr
	}

	// A Retry changes the DCID used to derive Initial keys without resetting the
	// packet number space, so the new epoch inherits the largest authenticated
	// packet number. Add it only after authentication, preventing a corrupt
	// packet from replacing working keys. QUIC permits at most one accepted
	// Retry, keeping two epochs sufficient for a connection.
	candidate := newQUICInitialKey(destConnID, s)
	candidate.largestPacketNumber = largestPacketNumber
	decrypted, packetNumber, err := decryptQUICInitialPacket(b, hdrLen, packetEnd, candidate.labels, candidate.largestPacketNumber, cache)
	if err != nil {
		return nil, err
	}
	candidate.largestPacketNumber = packetNumber
	if len(q.initialKeys) == 1 {
		q.initialKeys = append(q.initialKeys, candidate)
	} else {
		q.initialKeys[1] = candidate
	}
	return decrypted, nil
}

// decryptQUICInitialPacket removes header protection and decrypts one Initial
// packet with the supplied key set.
func decryptQUICInitialPacket(b []byte, hdrLen, packetEnd int, labels quicLabels, largestPacketNumber int64, cache *buf.Buffer) ([]byte, int64, error) {
	// Failed key epochs leave scratch data behind. Reset it before every attempt
	// so trying retained Retry keys does not consume the buffer cumulatively.
	cache.Reset()

	block, err := aes.NewCipher(labels.hp)
	if err != nil {
		return nil, -1, err
	}

	if hdrLen+4+16 > packetEnd {
		return nil, -1, errNotQUIC
	}

	mask := cache.Extend(block.BlockSize())
	block.Encrypt(mask, b[hdrLen+4:hdrLen+4+16])
	firstByte := b[0]
	// Long headers have their low four bits protected.
	firstByte ^= mask[0] & 0x0f
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

	if extHdrLen > packetEnd {
		return nil, -1, errNotQUIC
	}
	truncatedPacketNumber := int64(0)
	for _, b := range packetNumber {
		truncatedPacketNumber = truncatedPacketNumber<<8 | int64(b)
	}
	decodedPacketNumber := decodeQUICPacketNumber(packetNumberLength, largestPacketNumber, truncatedPacketNumber)

	data := b[extHdrLen:packetEnd]

	aesCipher, err := aes.NewCipher(labels.key)
	if err != nil {
		return nil, -1, err
	}
	aead, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, -1, err
	}

	// We only decrypt once, so we do not need to XOR it back.
	// https://github.com/quic-go/qtls-go1-20/blob/e132a0e6cb45e20ac0b705454849a11d09ba5a54/cipher_suites.go#L496
	iv := bytes.Clone(labels.iv)
	for i := 0; i < 8; i++ {
		iv[len(iv)-1-i] ^= byte(uint64(decodedPacketNumber) >> (8 * i))
	}
	dst := cache.Extend(len(data))
	decrypted, err := aead.Open(dst[:0], iv, data, extHdr)
	if err != nil {
		return nil, -1, errQUICDecryptionFailed
	}

	return decrypted, decodedPacketNumber, nil
}

// decodeQUICPacketNumber reconstructs a packet number from its truncated wire
// representation using the window from RFC 9000 Appendix A.3.
func decodeQUICPacketNumber(length int, largest, truncated int64) int64 {
	expected := largest + 1
	window := int64(1) << (length * 8)
	halfWindow := window / 2
	mask := window - 1
	candidate := (expected & ^mask) | truncated
	if candidate <= expected-halfWindow && candidate < 1<<62-window {
		return candidate + window
	}
	if candidate > expected+halfWindow && candidate >= window {
		return candidate - window
	}
	return candidate
}

// readQUICFrames validates the frames allowed in an Initial packet and retains
// CRYPTO frame data for ClientHello reassembly.
func (q *quicPacketSender) readQUICFrames(data []byte) error {
	buffer := buf.As(data)
	for !buffer.IsEmpty() {
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
			if _, err := quicvarint.Read(buffer); err != nil { // Field: Largest Acknowledged
				return io.ErrUnexpectedEOF
			}
			if _, err := quicvarint.Read(buffer); err != nil { // Field: ACK Delay
				return io.ErrUnexpectedEOF
			}
			ackRangeCount, err := quicvarint.Read(buffer) // Field: ACK Range Count
			if err != nil {
				return io.ErrUnexpectedEOF
			}
			if _, err := quicvarint.Read(buffer); err != nil { // Field: First ACK Range
				return io.ErrUnexpectedEOF
			}
			for i := uint64(0); i < ackRangeCount; i++ { // Field: ACK Range
				if _, err := quicvarint.Read(buffer); err != nil { // Field: ACK Range -> Gap
					return io.ErrUnexpectedEOF
				}
				if _, err := quicvarint.Read(buffer); err != nil { // Field: ACK Range -> ACK Range Length
					return io.ErrUnexpectedEOF
				}
			}
			if frameType == frameAckWithECN {
				if _, err := quicvarint.Read(buffer); err != nil { // Field: ECN Counts -> ECT0 Count
					return io.ErrUnexpectedEOF
				}
				if _, err := quicvarint.Read(buffer); err != nil { // Field: ECN Counts -> ECT1 Count
					return io.ErrUnexpectedEOF
				}
				if _, err := quicvarint.Read(buffer); err != nil { //nolint:misspell // Field: ECN Counts -> ECT-CE Count
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
			data, err := buffer.ReadBytes(int(length)) // Field: Crypto Data
			if err != nil {
				return io.ErrUnexpectedEOF
			}
			if err := q.addCryptoData(offset, data); err != nil {
				return err
			}
		case frameConnectionClose:
			if _, err := quicvarint.Read(buffer); err != nil { // Field: Error Code
				return io.ErrUnexpectedEOF
			}
			if _, err := quicvarint.Read(buffer); err != nil { // Field: Frame Type
				return io.ErrUnexpectedEOF
			}
			length, err := quicvarint.Read(buffer) // Field: Reason Phrase Length
			if err != nil || length > uint64(buffer.Len()) {
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
	return nil
}

// addCryptoData stores a bounded CRYPTO fragment, growing the buffer only as
// needed and tracking exact byte coverage across out-of-order, overlapping, or
// retransmitted frames.
func (q *quicPacketSender) addCryptoData(offset uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	length := uint64(len(data))
	if offset > maxCryptoStreamOffset || length > maxCryptoStreamOffset-offset {
		return io.ErrShortBuffer
	}
	end := offset + length

	q.lock.Lock()
	defer q.lock.Unlock()
	if q.closed {
		return nil
	}

	if end > uint64(cap(q.buffer)) {
		newBuffer := pool.Get(int(end))
		copy(newBuffer, q.buffer)
		_ = pool.Put(q.buffer)
		q.buffer = newBuffer
	} else if end > uint64(len(q.buffer)) {
		q.buffer = q.buffer[:end]
	}
	copy(q.buffer[offset:end], data)

	q.receivedCryptoData.setRange(int(offset), int(end))

	// The contiguous prefix only moves forward, allowing the bitmap to skip
	// complete words without rescanning the assembled prefix.
	if offset <= q.contiguousCryptoEnd && end > q.contiguousCryptoEnd {
		q.contiguousCryptoEnd = uint64(q.receivedCryptoData.firstUnset(int(q.contiguousCryptoEnd), len(q.buffer)))
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

	if q.contiguousCryptoEnd == 0 {
		return "", nil
	}

	if q.contiguousCryptoEnd >= tlsHandshakeHeaderLen {
		helloSize, err := clientHelloSize(q.buffer[:tlsHandshakeHeaderLen])
		if err != nil {
			return "", err
		}
		if helloSize > maxCryptoStreamOffset {
			return "", io.ErrShortBuffer
		}
	}

	domain, err := ReadClientHello(q.buffer[:q.contiguousCryptoEnd])
	if err != nil {
		var need *errNeedAtLeastData
		if errors.As(err, &need) {
			if need.length > maxCryptoStreamOffset {
				return "", io.ErrShortBuffer
			}
			return "", nil
		}
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

func newQUICInitialKey(destConnID []byte, s *quicStructure) quicInitialKey {
	return quicInitialKey{
		destConnID:          bytes.Clone(destConnID),
		labels:              expandLabels(destConnID, s),
		largestPacketNumber: -1,
	}
}

func expandLabels(destConnID []byte, s *quicStructure) quicLabels {
	initialSecret := hkdf.Extract(crypto.SHA256.New, destConnID, s.initialSalt)
	secret := hkdfExpandLabel(initialSecret, "client in", crypto.SHA256.Size())

	lp := s.labelPrefix

	return quicLabels{
		hp:  hkdfExpandLabel(secret, lp+" hp", 16),
		key: hkdfExpandLabel(secret, lp+" key", 16),
		iv:  hkdfExpandLabel(secret, lp+" iv", 12),
	}
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
