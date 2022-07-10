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

var fingerprints [][32]byte
var rwLock sync.Mutex
var defaultTLSConfig = &tls.Config{
	InsecureSkipVerify:    true,
	VerifyPeerCertificate: verifyPeerCertificate,
}
var verifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	fingerprints := fingerprints

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

func AddCertFingerprint(fingerprint string) error {
	fp := strings.Replace(fingerprint, ":", "", -1)
	fpByte, err := hex.DecodeString(fp)
	if err != nil {
		return err
	}

	if len(fpByte) != 32 {
		return fmt.Errorf("fingerprint string length error,need sha25 fingerprint")
	}

	rwLock.Lock()
	fingerprints = append(fingerprints, *(*[32]byte)(fpByte))
	rwLock.Unlock()
	return nil
}

func GetDefaultTLSConfig() *tls.Config {
	return defaultTLSConfig
}

func MixinTLSConfig(tlsConfig *tls.Config) *tls.Config {
	if tlsConfig == nil {
		return GetDefaultTLSConfig()
	}

	tlsConfig.InsecureSkipVerify = true
	tlsConfig.VerifyPeerCertificate = verifyPeerCertificate
	return tlsConfig
}
