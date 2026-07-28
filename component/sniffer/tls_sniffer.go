package sniffer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/sniffer"
)

var (
	errNotTLS         = errors.New("not TLS header")
	errNotClientHello = errors.New("not client hello")
)

const (
	tlsRecordHeaderLen          = 5
	tlsHandshakeHeaderLen       = 4
	tlsRecordTypeHandshake      = 0x16
	tlsHandshakeTypeClientHello = 0x01
	tlsMaxPlaintext             = 1 << 14
)

type errNeedAtLeastData struct {
	length int
	err    error
}

func (e *errNeedAtLeastData) Error() string {
	return fmt.Sprintf("%v, need at least length: %d", e.err, e.length)
}

func (e *errNeedAtLeastData) Unwrap() error {
	return e.err
}

var _ sniffer.Sniffer = (*TLSSniffer)(nil)

type TLSSniffer struct {
	*BaseSniffer
}

func NewTLSSniffer(snifferConfig SnifferConfig) (*TLSSniffer, error) {
	ports := snifferConfig.Ports
	if len(ports) == 0 {
		ports = utils.IntRanges[uint16]{utils.NewRange[uint16](443, 443)}
	}
	return &TLSSniffer{
		BaseSniffer: NewBaseSniffer(ports, C.TCP),
	}, nil
}

func (tls *TLSSniffer) Protocol() string {
	return "tls"
}

func (tls *TLSSniffer) SupportNetwork() C.NetWork {
	return C.TCP
}

func (tls *TLSSniffer) SniffData(bytes []byte) (string, error) {
	domain, err := SniffTLS(bytes)
	if err == nil {
		return *domain, nil
	} else {
		return "", err
	}
}

func IsValidTLSVersion(major, minor byte) bool {
	return major == 3
}

// ReadClientHello returns the server name as soon as its complete field is
// available in a ClientHello prefix, including the four-byte handshake header.
// https://github.com/golang/go/blob/master/src/crypto/tls/handshake_messages.go#L300
func ReadClientHello(data []byte) (*string, error) {
	if len(data) == 0 {
		return nil, &errNeedAtLeastData{length: 1, err: ErrNoClue}
	}
	if data[0] != tlsHandshakeTypeClientHello {
		return nil, errNotClientHello
	}
	if len(data) < tlsHandshakeHeaderLen {
		return nil, &errNeedAtLeastData{length: tlsHandshakeHeaderLen, err: ErrNoClue}
	}

	helloSize, err := clientHelloSize(data)
	if err != nil {
		return nil, err
	}
	if len(data) > helloSize {
		data = data[:helloSize]
	}
	need := func(length int) error {
		if length > helloSize {
			return errNotClientHello
		}
		if len(data) < length {
			return &errNeedAtLeastData{length: length, err: ErrNoClue}
		}
		return nil
	}

	offset := tlsHandshakeHeaderLen + 2 + 32 // legacy_version and random
	if err := need(offset + 1); err != nil {
		return nil, err
	}
	sessionIDLen := int(data[offset])
	if sessionIDLen > 32 {
		return nil, errNotClientHello
	}
	offset++
	if err := need(offset + sessionIDLen); err != nil {
		return nil, err
	}
	offset += sessionIDLen

	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	if err := need(offset + 2); err != nil {
		return nil, err
	}
	cipherSuiteLen := int(data[offset])<<8 | int(data[offset+1])
	if cipherSuiteLen%2 == 1 {
		return nil, errNotClientHello
	}
	offset += 2
	if err := need(offset + cipherSuiteLen); err != nil {
		return nil, err
	}
	offset += cipherSuiteLen

	if err := need(offset + 1); err != nil {
		return nil, err
	}
	compressionMethodsLen := int(data[offset])
	offset++
	if err := need(offset + compressionMethodsLen); err != nil {
		return nil, err
	}
	offset += compressionMethodsLen

	if offset == helloSize {
		return nil, errNotClientHello
	}
	if err := need(offset + 2); err != nil {
		return nil, err
	}

	extensionsLength := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	extensionsEnd := offset + extensionsLength
	if extensionsEnd != helloSize {
		return nil, errNotClientHello
	}

	for offset < extensionsEnd {
		if err := need(offset + 4); err != nil {
			return nil, err
		}
		extension := uint16(data[offset])<<8 | uint16(data[offset+1])
		length := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4
		extensionEnd := offset + length
		if extensionEnd > extensionsEnd {
			return nil, errNotClientHello
		}

		if extension == 0x00 { /* extensionServerName */
			if length < 2 {
				return nil, errNotClientHello
			}
			if err := need(offset + 2); err != nil {
				return nil, err
			}
			namesLen := int(data[offset])<<8 | int(data[offset+1])
			offset += 2
			namesEnd := offset + namesLen
			if namesEnd != extensionEnd {
				return nil, errNotClientHello
			}
			for offset < namesEnd {
				if err := need(offset + 3); err != nil {
					return nil, err
				}
				nameType := data[offset]
				nameLen := int(data[offset+1])<<8 | int(data[offset+2])
				offset += 3
				nameEnd := offset + nameLen
				if nameEnd > namesEnd {
					return nil, errNotClientHello
				}
				if err := need(nameEnd); err != nil {
					return nil, err
				}
				if nameType == 0 {
					serverName := string(data[offset:nameEnd])
					// An SNI value may not include a
					// trailing dot. See
					// https://tools.ietf.org/html/rfc6066#section-3.
					if strings.HasSuffix(serverName, ".") {
						return nil, errNotClientHello
					}

					return &serverName, nil
				}
				offset = nameEnd
			}
		} else {
			if extensionEnd == extensionsEnd {
				// This is the last extension, so its payload cannot contain a
				// later server_name extension that changes the verdict.
				return nil, errNotTLS
			}
			if err := need(extensionEnd); err != nil {
				return nil, err
			}
			offset = extensionEnd
		}
	}

	return nil, errNotTLS
}

func clientHelloSize(data []byte) (int, error) {
	if len(data) < tlsHandshakeHeaderLen {
		return 0, ErrNoClue
	}
	if data[0] != tlsHandshakeTypeClientHello {
		return 0, errNotClientHello
	}

	bodyLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	return tlsHandshakeHeaderLen + bodyLen, nil
}

func SniffTLS(b []byte) (*string, error) {
	var clientHello []byte
	wireOffset := 0

	for {
		if len(b)-wireOffset < tlsRecordHeaderLen {
			return nil, &errNeedAtLeastData{
				length: wireOffset + tlsRecordHeaderLen,
				err:    ErrNoClue,
			}
		}

		header := b[wireOffset : wireOffset+tlsRecordHeaderLen]
		if header[0] != tlsRecordTypeHandshake || !IsValidTLSVersion(header[1], header[2]) {
			return nil, errNotTLS
		}

		recordLen := int(binary.BigEndian.Uint16(header[3:]))
		// The initial ClientHello is plaintext, whose record payload is limited
		// to 2^14 bytes by every TLS version supported here.
		if recordLen > tlsMaxPlaintext {
			return nil, errNotTLS
		}
		if recordLen == 0 {
			return nil, errNotClientHello
		}

		payloadOffset := wireOffset + tlsRecordHeaderLen
		recordEnd := payloadOffset + recordLen
		payloadEnd := len(b)
		if payloadEnd > recordEnd {
			payloadEnd = recordEnd
		}
		if payloadEnd < payloadOffset {
			payloadEnd = payloadOffset
		}

		payload := b[payloadOffset:payloadEnd:payloadEnd]
		if wireOffset == 0 {
			clientHello = payload
		} else {
			clientHello = append(clientHello, payload...)
		}

		domain, err := ReadClientHello(clientHello)
		if err == nil {
			return domain, nil
		}
		var need *errNeedAtLeastData
		if !errors.As(err, &need) {
			return nil, err
		}

		if payloadEnd < recordEnd {
			// Translate the required ClientHello prefix length back to the wire
			// offset, stopping at this record boundary when another header is next.
			missing := need.length - len(clientHello)
			if remaining := recordEnd - payloadEnd; missing > remaining {
				missing = remaining
			}
			return nil, &errNeedAtLeastData{length: payloadEnd + missing, err: ErrNoClue}
		}
		wireOffset = recordEnd
	}
}
