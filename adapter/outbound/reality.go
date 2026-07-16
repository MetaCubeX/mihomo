package outbound

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	tlsC "github.com/metacubex/mihomo/component/tls"
)

type RealityOptions struct {
	PublicKey     string `proxy:"public-key"`
	Password      string `proxy:"password,omitempty"`
	ShortID       string `proxy:"short-id,omitempty"`
	Mldsa65Verify string `proxy:"mldsa65-verify,omitempty"`
	SpiderX       string `proxy:"spider-x,omitempty"`
	Show          bool   `proxy:"show,omitempty"`
	MasterKeyLog  string `proxy:"master-key-log,omitempty"`

	// Deprecated: REALITY always preserves the selected browser fingerprint.
	// Use an explicit legacy fingerprint such as chrome120 for legacy servers.
	SupportX25519MLKEM768 bool `proxy:"support-x25519mlkem768,omitempty"`
}

func (o RealityOptions) Parse() (*tlsC.RealityConfig, error) {
	publicKeyValue := o.PublicKey
	if o.Password != "" {
		publicKeyValue = o.Password
	}
	if publicKeyValue != "" {
		config := new(tlsC.RealityConfig)

		const x25519ScalarSize = 32
		publicKey, err := base64.RawURLEncoding.DecodeString(publicKeyValue)
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

		if o.Mldsa65Verify != "" {
			config.Mldsa65Verify, err = base64.RawURLEncoding.DecodeString(o.Mldsa65Verify)
			if err != nil || len(config.Mldsa65Verify) != 1952 {
				return nil, errors.New("invalid REALITY ML-DSA-65 verification key")
			}
		}
		config.SpiderX, config.SpiderY, err = parseRealitySpider(o.SpiderX)
		if err != nil {
			return nil, err
		}
		config.Show = o.Show
		if o.MasterKeyLog != "" && o.MasterKeyLog != "none" {
			config.KeyLogWriter, err = os.OpenFile(o.MasterKeyLog, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
			if err != nil {
				return nil, fmt.Errorf("open REALITY master key log: %w", err)
			}
		}

		return config, nil
	}
	return nil, nil
}

func parseRealitySpider(value string) (string, [10]int64, error) {
	if value == "" {
		value = "/"
	}
	if value[0] != '/' {
		return "", [10]int64{}, errors.New("invalid REALITY spider-x")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", [10]int64{}, fmt.Errorf("parse REALITY spider-x: %w", err)
	}
	query := parsed.Query()
	var ranges [10]int64
	parseRange := func(name string, index int) {
		value := query.Get(name)
		if value == "" {
			return
		}
		parts := strings.Split(value, "-")
		ranges[index], _ = strconv.ParseInt(parts[0], 10, 64)
		ranges[index+1] = ranges[index]
		if len(parts) > 1 {
			ranges[index+1], _ = strconv.ParseInt(parts[1], 10, 64)
		}
		query.Del(name)
	}
	parseRange("p", 0)
	parseRange("c", 2)
	parseRange("t", 4)
	parseRange("i", 6)
	parseRange("r", 8)
	parsed.RawQuery = query.Encode()
	return parsed.String(), ranges, nil
}
