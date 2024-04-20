package ca

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	C "github.com/metacubex/mihomo/constant"
)

var trustCerts []*x509.Certificate
var globalCertPool *x509.CertPool
var mutex sync.RWMutex
var errNotMatch = errors.New("certificate fingerprints do not match")

//go:embed ca-certificates.crt
var _CaCertificates []byte
var DisableEmbedCa, _ = strconv.ParseBool(os.Getenv("DISABLE_EMBED_CA"))
var DisableSystemCa, _ = strconv.ParseBool(os.Getenv("DISABLE_SYSTEM_CA"))

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
	if DisableSystemCa {
		globalCertPool = x509.NewCertPool()
	} else {
		globalCertPool, err = x509.SystemCertPool()
		if err != nil {
			globalCertPool = x509.NewCertPool()
		}
	}
	for _, cert := range trustCerts {
		globalCertPool.AddCert(cert)
	}
	if !DisableEmbedCa {
		globalCertPool.AppendCertsFromPEM(_CaCertificates)
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
	if globalCertPool == nil {
		mutex.Lock()
		defer mutex.Unlock()
		if globalCertPool != nil {
			return globalCertPool
		}
		initializeCertPool()
	}
	return globalCertPool
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
		return errNotMatch
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

// GetTLSConfig specified fingerprint, customCA and customCAString
func GetTLSConfig(tlsConfig *tls.Config, fingerprint string, customCA string, customCAString string) (*tls.Config, error) {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	var certificate []byte
	var err error
	if len(customCA) > 0 {
		certificate, err = os.ReadFile(C.Path.Resolve(customCA))
		if err != nil {
			return nil, fmt.Errorf("load ca error: %w", err)
		}
	} else if customCAString != "" {
		certificate = []byte(customCAString)
	}
	if len(certificate) > 0 {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(certificate) {
			return nil, fmt.Errorf("failed to parse certificate:\n\n %s", certificate)
		}
		tlsConfig.RootCAs = certPool
	} else {
		tlsConfig.RootCAs = getCertPool()
	}
	if len(fingerprint) > 0 {
		var fingerprintBytes *[32]byte
		fingerprintBytes, err = convertFingerprint(fingerprint)
		if err != nil {
			return nil, err
		}
		tlsConfig = GetGlobalTLSConfig(tlsConfig)
		tlsConfig.VerifyPeerCertificate = verifyFingerprint(fingerprintBytes)
		tlsConfig.InsecureSkipVerify = true
	}
	return tlsConfig, nil
}

// GetSpecifiedFingerprintTLSConfig specified fingerprint
func GetSpecifiedFingerprintTLSConfig(tlsConfig *tls.Config, fingerprint string) (*tls.Config, error) {
	return GetTLSConfig(tlsConfig, fingerprint, "", "")
}

func GetGlobalTLSConfig(tlsConfig *tls.Config) *tls.Config {
	tlsConfig, _ = GetTLSConfig(tlsConfig, "", "", "")
	return tlsConfig
}
