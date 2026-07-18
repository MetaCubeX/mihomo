package openvpn

import (
	"encoding/pem"
	"errors"
	"fmt"
)

const (
	tlsCryptV2ClientPEMType       = "OpenVPN tls-crypt-v2 client key"
	tlsCryptV2ClientKeyDataLength = 256
)

// TLSCryptV2 is the client-side tls-crypt-v2 protection state. Control packet
// encryption itself uses the first 256 bytes exactly like tls-crypt v1 with
// inverse/client direction. The remainder of the client PEM is the wrapped
// client key that must be appended to the initial V3 hard-reset packet.
type TLSCryptV2 struct {
	*TLSCrypt
	wrappedClientKey []byte
}

func NewTLSCryptV2(keyMaterial, wrappedClientKey []byte) (*TLSCryptV2, error) {
	if len(keyMaterial) != tlsCryptV2ClientKeyDataLength {
		return nil, fmt.Errorf("invalid tls-crypt-v2 key material length %d, expected %d", len(keyMaterial), tlsCryptV2ClientKeyDataLength)
	}
	if len(wrappedClientKey) == 0 {
		return nil, errors.New("missing wrapped tls-crypt-v2 client key")
	}
	crypt, err := NewTLSCrypt(keyMaterial, true)
	if err != nil {
		return nil, err
	}
	return &TLSCryptV2{
		TLSCrypt:         crypt,
		wrappedClientKey: cloneBytes(wrappedClientKey),
	}, nil
}

func (c *TLSCryptV2) WrappedClientKey() []byte {
	if c == nil {
		return nil
	}
	return cloneBytes(c.wrappedClientKey)
}

// DecodeTLSCryptV2ClientKey parses the standard OpenVPN client PEM. The PEM
// body is base64, not the hex-body format used by "OpenVPN Static key V1".
func DecodeTLSCryptV2ClientKey(input []byte) (keyMaterial, wrappedClientKey []byte, err error) {
	block, _ := pem.Decode(input)
	if block == nil || block.Type != tlsCryptV2ClientPEMType {
		return nil, nil, errors.New("invalid tls-crypt-v2 client PEM")
	}
	if len(block.Bytes) <= tlsCryptV2ClientKeyDataLength {
		return nil, nil, errors.New("tls-crypt-v2 client PEM missing wrapped key")
	}
	return cloneBytes(block.Bytes[:tlsCryptV2ClientKeyDataLength]),
		cloneBytes(block.Bytes[tlsCryptV2ClientKeyDataLength:]), nil
}
