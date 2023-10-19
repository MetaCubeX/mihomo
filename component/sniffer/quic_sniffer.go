package sniffer

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	_ "crypto/tls"
	"encoding/binary"
	"errors"
	"github.com/Dreamacro/clash/common/buf"
	"github.com/Dreamacro/clash/common/utils"
	C "github.com/Dreamacro/clash/constant"
	"github.com/metacubex/quic-go/quicvarint"
	"golang.org/x/crypto/hkdf"
	"io"
	_ "unsafe"
)

// Modified from https://github.com/v2fly/v2ray-core/blob/master/common/protocol/quic/sniff.go

const (
	versionDraft29 uint32 = 0xff00001d
	version1       uint32 = 0x1
)

type cipherSuiteTLS13 struct {
	ID     uint16
	KeyLen int
	AEAD   func(key, fixedNonce []byte) cipher.AEAD
	Hash   crypto.Hash
}

// github.com/quic-go/quic-go/internal/handshake/cipher_suite.go describes these cipher suite implementations are copied from the standard library crypto/tls package.
// So we can user go:linkname to implement the same feature.

//go:linkname aeadAESGCMTLS13 crypto/tls.aeadAESGCMTLS13
func aeadAESGCMTLS13(key, nonceMask []byte) cipher.AEAD

var (
	quicSaltOld  = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
	quicSalt     = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	initialSuite = &cipherSuiteTLS13{
		ID:     tls.TLS_AES_128_GCM_SHA256,
		KeyLen: 16,
		AEAD:   aeadAESGCMTLS13,
		Hash:   crypto.SHA256,
	}
	errNotQuic        = errors.New("not QUIC")
	errNotQuicInitial = errors.New("not QUIC initial packet")
)

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

func (quic QuicSniffer) Protocol() string {
	return "quic"
}

func (quic QuicSniffer) SupportNetwork() C.NetWork {
	return C.UDP
}

func (quic QuicSniffer) SniffData(b []byte) (string, error) {
	buffer := buf.As(b)
	typeByte, err := buffer.ReadByte()
	if err != nil {
		return "", errNotQuic
	}
	isLongHeader := typeByte&0x80 > 0
	if !isLongHeader || typeByte&0x40 == 0 {
		return "", errNotQuicInitial
	}

	vb, err := buffer.ReadBytes(4)
	if err != nil {
		return "", errNotQuic
	}

	versionNumber := binary.BigEndian.Uint32(vb)

	if versionNumber != 0 && typeByte&0x40 == 0 {
		return "", errNotQuic
	} else if versionNumber != versionDraft29 && versionNumber != version1 {
		return "", errNotQuic
	}

	if (typeByte&0x30)>>4 != 0x0 {
		return "", errNotQuicInitial
	}

	var destConnID []byte
	if l, err := buffer.ReadByte(); err != nil {
		return "", errNotQuic
	} else if destConnID, err = buffer.ReadBytes(int(l)); err != nil {
		return "", errNotQuic
	}

	if l, err := buffer.ReadByte(); err != nil {
		return "", errNotQuic
	} else if _, err := buffer.ReadBytes(int(l)); err != nil {
		return "", errNotQuic
	}

	tokenLen, err := quicvarint.Read(buffer)
	if err != nil || tokenLen > uint64(len(b)) {
		return "", errNotQuic
	}

	if _, err = buffer.ReadBytes(int(tokenLen)); err != nil {
		return "", errNotQuic
	}

	packetLen, err := quicvarint.Read(buffer)
	if err != nil {
		return "", errNotQuic
	}

	hdrLen := len(b) - int(buffer.Len())

	origPNBytes := make([]byte, 4)
	copy(origPNBytes, b[hdrLen:hdrLen+4])

	var salt []byte
	if versionNumber == version1 {
		salt = quicSalt
	} else {
		salt = quicSaltOld
	}
	initialSecret := hkdf.Extract(crypto.SHA256.New, destConnID, salt)
	secret := hkdfExpandLabel(crypto.SHA256, initialSecret, []byte{}, "client in", crypto.SHA256.Size())
	hpKey := hkdfExpandLabel(initialSuite.Hash, secret, []byte{}, "quic hp", initialSuite.KeyLen)
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return "", err
	}

	cache := buf.New()
	defer cache.Release()

	mask := cache.Extend(int(block.BlockSize()))
	block.Encrypt(mask, b[hdrLen+4:hdrLen+4+16])
	b[0] ^= mask[0] & 0xf
	for i := range b[hdrLen : hdrLen+4] {
		b[hdrLen+i] ^= mask[i+1]
	}
	packetNumberLength := b[0]&0x3 + 1
	var packetNumber uint32
	{
		n, err := buffer.ReadByte()
		if err != nil {
			return "", err
		}
		packetNumber = uint32(n)
	}

	if packetNumber != 0 && packetNumber != 1 {
		return "", errNotQuicInitial
	}

	extHdrLen := hdrLen + int(packetNumberLength)
	copy(b[extHdrLen:hdrLen+4], origPNBytes[packetNumberLength:])
	data := b[extHdrLen : int(packetLen)+hdrLen]

	key := hkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic key", 16)
	iv := hkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic iv", 12)
	c := aeadAESGCMTLS13(key, iv)
	nonce := cache.Extend(int(c.NonceSize()))
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], uint64(packetNumber))
	decrypted, err := c.Open(b[extHdrLen:extHdrLen], nonce, data, b[:extHdrLen])
	if err != nil {
		return "", err
	}
	buffer = buf.As(decrypted)

	cryptoLen := uint(0)
	cryptoData := make([]byte, buffer.Len())
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
				return "", io.ErrUnexpectedEOF
			}
			if _, err = quicvarint.Read(buffer); err != nil { // Field: ACK Delay
				return "", io.ErrUnexpectedEOF
			}
			ackRangeCount, err := quicvarint.Read(buffer) // Field: ACK Range Count
			if err != nil {
				return "", io.ErrUnexpectedEOF
			}
			if _, err = quicvarint.Read(buffer); err != nil { // Field: First ACK Range
				return "", io.ErrUnexpectedEOF
			}
			for i := 0; i < int(ackRangeCount); i++ { // Field: ACK Range
				if _, err = quicvarint.Read(buffer); err != nil { // Field: ACK Range -> Gap
					return "", io.ErrUnexpectedEOF
				}
				if _, err = quicvarint.Read(buffer); err != nil { // Field: ACK Range -> ACK Range Length
					return "", io.ErrUnexpectedEOF
				}
			}
			if frameType == 0x03 {
				if _, err = quicvarint.Read(buffer); err != nil { // Field: ECN Counts -> ECT0 Count
					return "", io.ErrUnexpectedEOF
				}
				if _, err = quicvarint.Read(buffer); err != nil { // Field: ECN Counts -> ECT1 Count
					return "", io.ErrUnexpectedEOF
				}
				if _, err = quicvarint.Read(buffer); err != nil { //nolint:misspell // Field: ECN Counts -> ECT-CE Count
					return "", io.ErrUnexpectedEOF
				}
			}
		case 0x06: // CRYPTO frame, we will use this frame
			offset, err := quicvarint.Read(buffer) // Field: Offset
			if err != nil {
				return "", io.ErrUnexpectedEOF
			}
			length, err := quicvarint.Read(buffer) // Field: Length
			if err != nil || length > uint64(buffer.Len()) {
				return "", io.ErrUnexpectedEOF
			}
			if cryptoLen < uint(offset+length) {
				cryptoLen = uint(offset + length)
			}
			if _, err := buffer.Read(cryptoData[offset : offset+length]); err != nil { // Field: Crypto Data
				return "", io.ErrUnexpectedEOF
			}
		case 0x1c: // CONNECTION_CLOSE frame, only 0x1c is permitted in initial packet
			if _, err = quicvarint.Read(buffer); err != nil { // Field: Error Code
				return "", io.ErrUnexpectedEOF
			}
			if _, err = quicvarint.Read(buffer); err != nil { // Field: Frame Type
				return "", io.ErrUnexpectedEOF
			}
			length, err := quicvarint.Read(buffer) // Field: Reason Phrase Length
			if err != nil {
				return "", io.ErrUnexpectedEOF
			}
			if _, err := buffer.ReadBytes(int(length)); err != nil { // Field: Reason Phrase
				return "", io.ErrUnexpectedEOF
			}
		default:
			// Only above frame types are permitted in initial packet.
			// See https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.2-8
			return "", errNotQuicInitial
		}
	}

	domain, err := ReadClientHello(cryptoData[:cryptoLen])
	if err != nil {
		return "", err
	}

	return *domain, nil
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
