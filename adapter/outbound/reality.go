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
	ShortID   string `proxy:"short-id"`
}

func (o RealityOptions) Parse() (*tlsC.RealityConfig, error) {
	if o.PublicKey != "" {
		config := new(tlsC.RealityConfig)

		const x25519ScalarSize = 32
		var publicKey [x25519ScalarSize]byte
		n, err := base64.RawURLEncoding.Decode(publicKey[:], []byte(o.PublicKey))
		if err != nil || n != x25519ScalarSize {
			return nil, errors.New("invalid REALITY public key")
		}
		config.PublicKey, err = ecdh.X25519().NewPublicKey(publicKey[:])
		if err != nil {
			return nil, fmt.Errorf("fail to create REALITY public key: %w", err)
		}

		n, err = hex.Decode(config.ShortID[:], []byte(o.ShortID))
		if err != nil || n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short ID")
		}

		return config, nil
	}
	return nil, nil
}
