package echparser

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// export from std's crypto/tls/ech.go

const extensionEncryptedClientHello = 0xfe0d

type ECHCipher struct {
	KDFID  uint16
	AEADID uint16
}

type ECHExtension struct {
	Type uint16
	Data []byte
}

type ECHConfig struct {
	raw []byte

	Version uint16
	Length  uint16

	ConfigID             uint8
	KemID                uint16
	PublicKey            []byte
	SymmetricCipherSuite []ECHCipher

	MaxNameLength uint8
	PublicName    []byte
	Extensions    []ECHExtension
}

var ErrMalformedECHConfigList = errors.New("tls: malformed ECHConfigList")

type EchConfigErr struct {
	field string
}

func (e *EchConfigErr) Error() string {
	if e.field == "" {
		return "tls: malformed ECHConfig"
	}
	return fmt.Sprintf("tls: malformed ECHConfig, invalid %s field", e.field)
}

func ParseECHConfig(enc []byte) (skip bool, ec ECHConfig, err error) {
	s := cryptobyte.String(enc)
	ec.raw = []byte(enc)
	if !s.ReadUint16(&ec.Version) {
		return false, ECHConfig{}, &EchConfigErr{"version"}
	}
	if !s.ReadUint16(&ec.Length) {
		return false, ECHConfig{}, &EchConfigErr{"length"}
	}
	if len(ec.raw) < int(ec.Length)+4 {
		return false, ECHConfig{}, &EchConfigErr{"length"}
	}
	ec.raw = ec.raw[:ec.Length+4]
	if ec.Version != extensionEncryptedClientHello {
		s.Skip(int(ec.Length))
		return true, ECHConfig{}, nil
	}
	if !s.ReadUint8(&ec.ConfigID) {
		return false, ECHConfig{}, &EchConfigErr{"config_id"}
	}
	if !s.ReadUint16(&ec.KemID) {
		return false, ECHConfig{}, &EchConfigErr{"kem_id"}
	}
	if !s.ReadUint16LengthPrefixed((*cryptobyte.String)(&ec.PublicKey)) {
		return false, ECHConfig{}, &EchConfigErr{"public_key"}
	}
	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return false, ECHConfig{}, &EchConfigErr{"cipher_suites"}
	}
	for !cipherSuites.Empty() {
		var c ECHCipher
		if !cipherSuites.ReadUint16(&c.KDFID) {
			return false, ECHConfig{}, &EchConfigErr{"cipher_suites kdf_id"}
		}
		if !cipherSuites.ReadUint16(&c.AEADID) {
			return false, ECHConfig{}, &EchConfigErr{"cipher_suites aead_id"}
		}
		ec.SymmetricCipherSuite = append(ec.SymmetricCipherSuite, c)
	}
	if !s.ReadUint8(&ec.MaxNameLength) {
		return false, ECHConfig{}, &EchConfigErr{"maximum_name_length"}
	}
	var publicName cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&publicName) {
		return false, ECHConfig{}, &EchConfigErr{"public_name"}
	}
	ec.PublicName = publicName
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return false, ECHConfig{}, &EchConfigErr{"extensions"}
	}
	for !extensions.Empty() {
		var e ECHExtension
		if !extensions.ReadUint16(&e.Type) {
			return false, ECHConfig{}, &EchConfigErr{"extensions type"}
		}
		if !extensions.ReadUint16LengthPrefixed((*cryptobyte.String)(&e.Data)) {
			return false, ECHConfig{}, &EchConfigErr{"extensions data"}
		}
		ec.Extensions = append(ec.Extensions, e)
	}

	return false, ec, nil
}

// ParseECHConfigList parses a draft-ietf-tls-esni-18 ECHConfigList, returning a
// slice of parsed ECHConfigs, in the same order they were parsed, or an error
// if the list is malformed.
func ParseECHConfigList(data []byte) ([]ECHConfig, error) {
	s := cryptobyte.String(data)
	var length uint16
	if !s.ReadUint16(&length) {
		return nil, ErrMalformedECHConfigList
	}
	if length != uint16(len(data)-2) {
		return nil, ErrMalformedECHConfigList
	}
	var configs []ECHConfig
	for len(s) > 0 {
		if len(s) < 4 {
			return nil, errors.New("tls: malformed ECHConfig")
		}
		configLen := uint16(s[2])<<8 | uint16(s[3])
		skip, ec, err := ParseECHConfig(s)
		if err != nil {
			return nil, err
		}
		s = s[configLen+4:]
		if !skip {
			configs = append(configs, ec)
		}
	}
	return configs, nil
}
