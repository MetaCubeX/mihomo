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

	CN "github.com/Dreamacro/clash/common/net"

	xtls "github.com/xtls/go"
)

var tlsCertificates = make([]tls.Certificate, 0)

var mutex sync.RWMutex
var errNotMacth error = errors.New("certificate fingerprints do not match")

func AddCertificate(privateKey, certificate string) error {
	mutex.Lock()
	defer mutex.Unlock()
	if cert, err := CN.ParseCert(certificate, privateKey); err != nil {
		return err
	} else {
		tlsCertificates = append(tlsCertificates, cert)
	}
	return nil
}

func GetCertificates() []tls.Certificate {
	mutex.RLock()
	defer mutex.RUnlock()
	return tlsCertificates
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
			Certificates: tlsCertificates,
		}
	}
	tlsConfig.Certificates = append(tlsConfig.Certificates, tlsCertificates...)
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
	xtlsCerts := make([]xtls.Certificate, len(tlsCertificates))
	for _, cert := range tlsCertificates {
		tlsSsaList := make([]xtls.SignatureScheme, len(cert.SupportedSignatureAlgorithms))
		for _, ssa := range cert.SupportedSignatureAlgorithms {
			tlsSsa := xtls.SignatureScheme(ssa)
			tlsSsaList = append(tlsSsaList, tlsSsa)
		}
		xtlsCert := xtls.Certificate{
			Certificate:                  cert.Certificate,
			PrivateKey:                   cert.PrivateKey,
			OCSPStaple:                   cert.OCSPStaple,
			SignedCertificateTimestamps:  cert.SignedCertificateTimestamps,
			Leaf:                         cert.Leaf,
			SupportedSignatureAlgorithms: tlsSsaList,
		}
		xtlsCerts = append(xtlsCerts, xtlsCert)
	}
	if tlsConfig == nil {
		return &xtls.Config{
			Certificates: xtlsCerts,
		}
	}

	tlsConfig.Certificates = xtlsCerts
	return tlsConfig
}
