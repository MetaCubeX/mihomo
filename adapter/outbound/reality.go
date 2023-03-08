package outbound

import (
	"encoding/base64"
	"encoding/hex"
	"errors"

	tlsC "github.com/Dreamacro/clash/component/tls"

	"golang.org/x/crypto/curve25519"
)

type RealityOptions struct {
	ServerName string `proxy:"server-name"`
	PublicKey  string `proxy:"public-key"`
	ShortID    string `proxy:"short-id"`
}

func (o RealityOptions) Parse() (*tlsC.RealityConfig, error) {
	if o.PublicKey != "" || o.ServerName != "" {
		if o.PublicKey != "" && o.ServerName != "" {
			config := new(tlsC.RealityConfig)

			n, err := base64.RawURLEncoding.Decode(config.PublicKey[:], []byte(o.PublicKey))
			if err != nil || n != curve25519.ScalarSize {
				return nil, errors.New("invalid REALITY public key")
			}

			config.ShortID, err = hex.DecodeString(o.ShortID)
			if err != nil {
				return nil, errors.New("invalid REALITY short ID")
			}

			config.ServerName = o.ServerName

			return config, nil
		}
		return nil, errors.New("invalid REALITY protocol option")
	}
	return nil, nil
}
