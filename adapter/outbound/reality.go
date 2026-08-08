package outbound

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	tlsC "github.com/metacubex/mihomo/component/tls"
)

type RealityOptions struct {
	PublicKey string `proxy:"public-key"`
	ShortID   string `proxy:"short-id,omitempty"`

	SupportX25519MLKEM768 bool `proxy:"support-x25519mlkem768,omitempty"`
	ClientVer             string `proxy:"client-ver,omitempty"` // 覆盖 REALITY 声明的客户端版本, 如 "26.7.28"
}

func (o RealityOptions) Parse() (*tlsC.RealityConfig, error) {
	if o.PublicKey != "" {
		config := new(tlsC.RealityConfig)
		config.SupportX25519MLKEM768 = o.SupportX25519MLKEM768

		const x25519ScalarSize = 32
		publicKey, err := base64.RawURLEncoding.DecodeString(o.PublicKey)
		if err != nil || len(publicKey) != x25519ScalarSize {
			return nil, errors.New("invalid REALITY public key")
		}
		config.PublicKey, err = ecdh.X25519().NewPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("fail to create REALITY public key: %w", err)
		}

		n := hex.DecodedLen(len(o.ShortID))
		if n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short id")
		}
		n, err = hex.Decode(config.ShortID[:], []byte(o.ShortID))
		if err != nil || n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short ID")
		}

		if o.ClientVer != "" {
			var a, b, c int
			if _, err := fmt.Sscanf(o.ClientVer, "%d.%d.%d", &a, &b, &c); err != nil {
				return nil, fmt.Errorf("invalid REALITY client-ver %q: %w", o.ClientVer, err)
			}
			config.ClientVer = [3]byte{byte(a), byte(b), byte(c)}
		}

		return config, nil
	}
	return nil, nil
}
