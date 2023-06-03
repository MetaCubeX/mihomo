package tls

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	xtls "github.com/xtls/go"
)

var trustCerts []*x509.Certificate
var certPool *x509.CertPool
var mutex sync.RWMutex
var errNotMacth error = errors.New("certificate fingerprints do not match")

func AddCertificate(certificate string) error {
	mutex.Lock()
	defer mutex.Unlock()
	if certificate == "" {
		return fmt.Errorf("certificate is empty")
	}
	if cert, err := x509.ParseCertificate([]byte(certificate)); err == nil {
		trustCerts = append(trustCerts, cert)
		return nil
	} else {
		return fmt.Errorf("add certificate failed")
	}
}

func initializeCertPool() {
	var err error
	certPool, err = x509.SystemCertPool()
	if err != nil {
		certPool = x509.NewCertPool()
	}
	for _, cert := range trustCerts {
		certPool.AddCert(cert)
	}
}

func ResetCertificate() {
	mutex.Lock()
	defer mutex.Unlock()
	trustCerts = nil
	initializeCertPool()
}

func getCertPool() *x509.CertPool {
	if len(trustCerts) == 0 {
		return nil
	}
	if certPool == nil {
		mutex.Lock()
		defer mutex.Unlock()
		if certPool != nil {
			return certPool
		}
		initializeCertPool()
	}
	return certPool
}

func verifyFingerprint(fingerprint *[32]byte) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// ssl pining
		for i := range rawCerts {
			rawCert := rawCerts[i]
			cert, err := x509.ParseCertificate(rawCert)
			if err == nil {
				hash := sha256.Sum256(cert.Raw)
				if bytes.Equal(fingerprint[:], hash[:]) {
					return nil
				}
			}
		}
		return errNotMacth
	}
}

func convertFingerprint(fingerprint string) (*[32]byte, error) {
	fingerprint = strings.TrimSpace(strings.Replace(fingerprint, ":", "", -1))
	fpByte, err := hex.DecodeString(fingerprint)
	if err != nil {
		return nil, err
	}

	if len(fpByte) != 32 {
		return nil, fmt.Errorf("fingerprint string length error,need sha256 fingerprint")
	}
	return (*[32]byte)(fpByte), nil
}

func GetDefaultTLSConfig() *tls.Config {
	return GetGlobalTLSConfig(nil)
}

// GetSpecifiedFingerprintTLSConfig specified fingerprint
func GetSpecifiedFingerprintTLSConfig(tlsConfig *tls.Config, fingerprint string) (*tls.Config, error) {
	if fingerprintBytes, err := convertFingerprint(fingerprint); err != nil {
		return nil, err
	} else {
		tlsConfig = GetGlobalTLSConfig(tlsConfig)
		tlsConfig.VerifyPeerCertificate = verifyFingerprint(fingerprintBytes)
		tlsConfig.InsecureSkipVerify = true
		return tlsConfig, nil
	}
}

func GetGlobalTLSConfig(tlsConfig *tls.Config) *tls.Config {
	certPool := getCertPool()
	if tlsConfig == nil {
		return &tls.Config{
			RootCAs: certPool,
		}
	}
	tlsConfig.RootCAs = certPool
	return tlsConfig
}

// GetSpecifiedFingerprintXTLSConfig specified fingerprint
func GetSpecifiedFingerprintXTLSConfig(tlsConfig *xtls.Config, fingerprint string) (*xtls.Config, error) {
	if fingerprintBytes, err := convertFingerprint(fingerprint); err != nil {
		return nil, err
	} else {
		tlsConfig = GetGlobalXTLSConfig(tlsConfig)
		tlsConfig.VerifyPeerCertificate = verifyFingerprint(fingerprintBytes)
		tlsConfig.InsecureSkipVerify = true
		return tlsConfig, nil
	}
}

func GetGlobalXTLSConfig(tlsConfig *xtls.Config) *xtls.Config {
	certPool := getCertPool()
	if tlsConfig == nil {
		return &xtls.Config{
			RootCAs: certPool,
		}
	}

	tlsConfig.RootCAs = certPool
	return tlsConfig
}
