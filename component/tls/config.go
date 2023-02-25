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

var trustCert,_ = x509.SystemCertPool()

var mutex sync.RWMutex
var errNotMacth error = errors.New("certificate fingerprints do not match")

func AddCertificate(certificate string) error {
	mutex.Lock()
	defer mutex.Unlock()
	if certificate == "" {
		return fmt.Errorf("certificate is empty")
	}
	if ok := trustCert.AppendCertsFromPEM([]byte(certificate)); !ok {
		return fmt.Errorf("add certificate failed")
	}
	return nil
}

func ResetCertificate(){
	mutex.Lock()
	defer mutex.Unlock()
	trustCert,_=x509.SystemCertPool()
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
	if tlsConfig == nil {
		return &tls.Config{
			RootCAs: trustCert,
		}
	}
	tlsConfig.RootCAs = trustCert
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
	if tlsConfig == nil {
		return &xtls.Config{
			RootCAs: trustCert,
		}
	}

	tlsConfig.RootCAs = trustCert
	return tlsConfig
}
