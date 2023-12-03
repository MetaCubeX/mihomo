package sniffer

import (
	"encoding/binary"
	"errors"
	"strings"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/sniffer"
)

var (
	errNotTLS         = errors.New("not TLS header")
	errNotClientHello = errors.New("not client hello")
)

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

// ReadClientHello returns server name (if any) from TLS client hello message.
// https://github.com/golang/go/blob/master/src/crypto/tls/handshake_messages.go#L300
func ReadClientHello(data []byte) (*string, error) {
	if len(data) < 42 {
		return nil, ErrNoClue
	}
	sessionIDLen := int(data[38])
	if sessionIDLen > 32 || len(data) < 39+sessionIDLen {
		return nil, ErrNoClue
	}
	data = data[39+sessionIDLen:]
	if len(data) < 2 {
		return nil, ErrNoClue
	}
	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return nil, errNotClientHello
	}
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		return nil, ErrNoClue
	}
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return nil, ErrNoClue
	}
	data = data[1+compressionMethodsLen:]

	if len(data) == 0 {
		return nil, errNotClientHello
	}
	if len(data) < 2 {
		return nil, errNotClientHello
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		return nil, errNotClientHello
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return nil, errNotClientHello
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return nil, errNotClientHello
		}

		if extension == 0x00 { /* extensionServerName */
			d := data[:length]
			if len(d) < 2 {
				return nil, errNotClientHello
			}
			namesLen := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if len(d) != namesLen {
				return nil, errNotClientHello
			}
			for len(d) > 0 {
				if len(d) < 3 {
					return nil, errNotClientHello
				}
				nameType := d[0]
				nameLen := int(d[1])<<8 | int(d[2])
				d = d[3:]
				if len(d) < nameLen {
					return nil, errNotClientHello
				}
				if nameType == 0 {
					serverName := string(d[:nameLen])
					// An SNI value may not include a
					// trailing dot. See
					// https://tools.ietf.org/html/rfc6066#section-3.
					if strings.HasSuffix(serverName, ".") {
						return nil, errNotClientHello
					}

					return &serverName, nil
				}

				d = d[nameLen:]
			}
		}
		data = data[length:]
	}

	return nil, errNotTLS
}

func SniffTLS(b []byte) (*string, error) {
	if len(b) < 5 {
		return nil, ErrNoClue
	}

	if b[0] != 0x16 /* TLS Handshake */ {
		return nil, errNotTLS
	}
	if !IsValidTLSVersion(b[1], b[2]) {
		return nil, errNotTLS
	}
	headerLen := int(binary.BigEndian.Uint16(b[3:5]))
	if 5+headerLen > len(b) {
		return nil, ErrNoClue
	}

	domain, err := ReadClientHello(b[5 : 5+headerLen])
	if err == nil {
		return domain, nil
	}
	return nil, err
}
