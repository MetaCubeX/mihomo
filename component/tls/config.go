package tls

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

var globalFingerprints [][32]byte
var mutex sync.Mutex

func verifyPeerCertificateAndFingerprints(fingerprints [][32]byte, insecureSkipVerify bool) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if insecureSkipVerify {
			return nil
		}

		var preErr error
		for i := range rawCerts {
			rawCert := rawCerts[i]
			cert, err := x509.ParseCertificate(rawCert)
			if err == nil {
				opts := x509.VerifyOptions{
					CurrentTime: time.Now(),
				}

				if _, err := cert.Verify(opts); err == nil {
					return nil
				} else {
					fingerprint := sha256.Sum256(cert.Raw)
					for _, fp := range fingerprints {
						if bytes.Equal(fingerprint[:], fp[:]) {
							return nil
						}
					}

					preErr = err
				}
			}
		}

		return preErr
	}
}

func AddCertFingerprint(fingerprint string) error {
	fpByte, err2 := convertFingerprint(fingerprint)
	if err2 != nil {
		return err2
	}

	mutex.Lock()
	globalFingerprints = append(globalFingerprints, *fpByte)
	mutex.Unlock()
	return nil
}

func convertFingerprint(fingerprint string) (*[32]byte, error) {
	fp := strings.Replace(fingerprint, ":", "", -1)
	fpByte, err := hex.DecodeString(fp)
	if err != nil {
		return nil, err
	}

	if len(fpByte) != 32 {
		return nil, fmt.Errorf("fingerprint string length error,need sha25 fingerprint")
	}
	return (*[32]byte)(fpByte), nil
}

func GetDefaultTLSConfig() *tls.Config {
	return MixinTLSConfig(nil)
}

// GetTLSConfigWithSpecifiedFingerprint specified fingerprint
func GetTLSConfigWithSpecifiedFingerprint(tlsConfig *tls.Config, fingerprint string) (*tls.Config, error) {
	if fingerprintBytes, err := convertFingerprint(fingerprint); err != nil {
		return nil, err
	} else {
		if tlsConfig == nil {
			return &tls.Config{
				InsecureSkipVerify:    true,
				VerifyPeerCertificate: verifyPeerCertificateAndFingerprints([][32]byte{*fingerprintBytes}, false),
			}, nil
		} else {
			tlsConfig.VerifyPeerCertificate = verifyPeerCertificateAndFingerprints([][32]byte{*fingerprintBytes}, tlsConfig.InsecureSkipVerify)
			tlsConfig.InsecureSkipVerify = true
			return tlsConfig, nil
		}
	}
}

func MixinTLSConfig(tlsConfig *tls.Config) *tls.Config {
	if tlsConfig == nil {
		return &tls.Config{
			InsecureSkipVerify:    true,
			VerifyPeerCertificate: verifyPeerCertificateAndFingerprints(globalFingerprints, false),
		}
	}

	tlsConfig.VerifyPeerCertificate = verifyPeerCertificateAndFingerprints(globalFingerprints, tlsConfig.InsecureSkipVerify)
	tlsConfig.InsecureSkipVerify = true
	return tlsConfig
}
