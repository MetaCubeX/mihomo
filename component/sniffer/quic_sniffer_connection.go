package sniffer

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/quic-go/quicvarint"
	"golang.org/x/crypto/hkdf"
)

type quicDataBlock struct {
	offset uint64
	length uint64
	data   []byte
}

var _ constant.PacketSender = (*quicConnection)(nil)

type quicConnection struct {
	lock     sync.RWMutex
	buffer   []quicDataBlock
	sender   constant.PacketSender
	result   string
	override bool

	chClose chan struct{}
	closed  bool
}

func (conn *quicConnection) TryAssemble() error {
	conn.lock.RLock()

	if conn.buffer == nil {
		conn.lock.RUnlock()
		return nil
	}

	var frameLen uint64
	for _, fragment := range conn.buffer {
		frameLen += fragment.length
	}

	buffer := buf.NewSize(int(frameLen))

	var index uint64
	var length int

loop:
	for {
		for _, fragment := range conn.buffer {
			if fragment.offset == index {
				buffer.Write(fragment.data)
				index = fragment.offset + fragment.length
				length++
				continue loop
			}
		}

		break
	}

	domain, err := ReadClientHello(buffer.Bytes())
	if err != nil {
		conn.lock.RUnlock()
		return err
	}
	conn.lock.RUnlock()

	conn.lock.Lock()
	conn.result = *domain
	conn.lock.Unlock()
	conn.close()

	return err
}

func (conn *quicConnection) close() {
	conn.lock.Lock()
	if !conn.closed {
		close(conn.chClose)
		conn.closed = true
	}
	conn.lock.Unlock()
}

// Send will send PacketAdapter nonblocking
// the implement must call UDPPacket.Drop() inside Send
func (q *quicConnection) Send(current constant.PacketAdapter) {
	defer q.sender.Send(current)

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

// Process is a blocking loop to send PacketAdapter to PacketConn and update the WriteBackProxy
func (q *quicConnection) Process(conn constant.PacketConn, proxy constant.WriteBackProxy) {
	q.sender.Process(conn, proxy)
}

// ResolveUDP wait sniffer recv all fragments and update the domain
func (q *quicConnection) ResolveUDP(data *constant.Metadata) error {
	select {
	case <-q.chClose:
		q.lock.RLock()
		replaceDomain(data, q.result, q.override)
		q.lock.RUnlock()
		break
	case <-time.After(quicWaitConn):
		q.close()
	}

	return q.sender.ResolveUDP(data)
}

// Close stop the Process loop
func (q *quicConnection) Close() {
	q.sender.Close()
	q.close()
}

func (conn *quicConnection) readQuicData(b []byte) error {
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

			conn.lock.RLock()
			if conn.buffer == nil {
				conn.lock.RUnlock()
				// sniffDone() was called, return the connection
				return nil
			}
			conn.lock.RUnlock()

			data = make([]byte, length)

			if _, err := buffer.Read(data); err != nil { // Field: Crypto Data
				return io.ErrUnexpectedEOF
			}

			conn.lock.Lock()
			conn.buffer = append(conn.buffer, quicDataBlock{
				offset: offset,
				length: length,
				data:   data,
			})
			conn.lock.Unlock()
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

	_ = conn.TryAssemble()

	return nil
}
