package encryption

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// NewClient new client from encryption string
// maybe return a nil *ClientInstance without any error, that means don't need to encrypt
func NewClient(encryption string) (*ClientInstance, error) {
	switch encryption {
	case "", "none": // We will not reject empty string like xray-core does, because we need to ensure compatibility
		return nil, nil
	}
	if s := strings.Split(encryption, "."); len(s) >= 4 && s[0] == "mlkem768x25519plus" {
		var xorMode uint32
		switch s[1] {
		case "native":
		case "xorpub":
			xorMode = 1
		case "random":
			xorMode = 2
		default:
			return nil, fmt.Errorf("invaild vless encryption value: %s", encryption)
		}
		var seconds uint32
		switch s[2] {
		case "1rtt":
		case "0rtt":
			seconds = 1
		default:
			return nil, fmt.Errorf("invaild vless encryption value: %s", encryption)
		}
		var nfsPKeysBytes [][]byte
		for _, r := range s[3:] {
			b, err := base64.RawURLEncoding.DecodeString(r)
			if err != nil {
				return nil, fmt.Errorf("invaild vless encryption value: %s", encryption)
			}
			if len(b) != X25519PasswordSize && len(b) != MLKEM768ClientLength {
				return nil, fmt.Errorf("invaild vless encryption value: %s", encryption)
			}
			nfsPKeysBytes = append(nfsPKeysBytes, b)
		}
		client := &ClientInstance{}
		if err := client.Init(nfsPKeysBytes, xorMode, seconds); err != nil {
			return nil, fmt.Errorf("failed to use encryption: %w", err)
		}
		return client, nil
	}
	return nil, fmt.Errorf("invaild vless encryption value: %s", encryption)
}

// NewServer new server from decryption string
// maybe return a nil *ServerInstance without any error, that means don't need to decrypt
func NewServer(decryption string) (*ServerInstance, error) {
	switch decryption {
	case "", "none": // We will not reject empty string like xray-core does, because we need to ensure compatibility
		return nil, nil
	}
	if s := strings.Split(decryption, "."); len(s) >= 4 && s[0] == "mlkem768x25519plus" {
		var xorMode uint32
		switch s[1] {
		case "native":
		case "xorpub":
			xorMode = 1
		case "random":
			xorMode = 2
		default:
			return nil, fmt.Errorf("invaild vless decryption value: %s", decryption)
		}
		var seconds uint32
		if s[2] != "1rtt" {
			t := strings.TrimSuffix(s[2], "s")
			if t == s[0] {
				return nil, fmt.Errorf("invaild vless decryption value: %s", decryption)
			}
			i, err := strconv.Atoi(t)
			if err != nil {
				return nil, fmt.Errorf("invaild vless decryption value: %s", decryption)
			}
			seconds = uint32(i)
		}
		var nfsSKeysBytes [][]byte
		for _, r := range s[3:] {
			b, err := base64.RawURLEncoding.DecodeString(r)
			if err != nil {
				return nil, fmt.Errorf("invaild vless decryption value: %s", decryption)
			}
			if len(b) != X25519PrivateKeySize && len(b) != MLKEM768SeedLength {
				return nil, fmt.Errorf("invaild vless decryption value: %s", decryption)
			}
			nfsSKeysBytes = append(nfsSKeysBytes, b)
		}
		server := &ServerInstance{}
		if err := server.Init(nfsSKeysBytes, xorMode, seconds); err != nil {
			return nil, fmt.Errorf("failed to use decryption: %w", err)
		}
		return server, nil
	}
	return nil, fmt.Errorf("invaild vless decryption value: %s", decryption)
}
