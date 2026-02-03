package ca

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/metacubex/tls"
)

// NewFingerprintVerifier returns a function that verifies whether a certificate's SHA-256 fingerprint matches the given one.
func NewFingerprintVerifier(fingerprint string, time func() time.Time) (func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error, error) {
	switch fingerprint {
	case "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized": // WTF???
		return nil, fmt.Errorf("`fingerprint` is used for TLS certificate pinning. If you need to specify the browser fingerprint, use `client-fingerprint`")
	}
	fingerprint = strings.TrimSpace(strings.Replace(fingerprint, ":", "", -1))
	fpByte, err := hex.DecodeString(fingerprint)
	if err != nil {
		return nil, fmt.Errorf("fingerprint string decode error: %w", err)
	}

	if len(fpByte) != 32 {
		return nil, fmt.Errorf("fingerprint string length error,need sha256 fingerprint")
	}

	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// ssl pining
		for i, rawCert := range rawCerts {
			hash := sha256.Sum256(rawCert)
			if bytes.Equal(fpByte, hash[:]) {
				if i > 0 {

					// When the fingerprint matches a non-leaf certificate,
					// the certificate chain validity is verified using the certificate as the trusted root certificate.
					//
					// Currently, we do not verify that the SNI matches the certificate's DNS name,
					// but we do verify the validity of the child certificate,
					// including the issuance time and whether the child certificate was issued by the parent certificate.

					certs := make([]*x509.Certificate, i+1) // stop at i
					for j := range certs {
						cert, err := x509.ParseCertificate(rawCerts[j])
						if err != nil {
							return err
						}
						certs[j] = cert
					}
					opts := x509.VerifyOptions{
						Roots:         x509.NewCertPool(),
						Intermediates: x509.NewCertPool(),
					}
					if time != nil {
						opts.CurrentTime = time()
					}
					opts.Roots.AddCert(certs[i])
					for _, cert := range certs[1:] {
						opts.Intermediates.AddCert(cert)
					}
					_, err := certs[0].Verify(opts)
					return err
				}
				return nil
			}
		}
		return errNotMatch
	}, nil
}

func NewConnectionVerifier(fingerprint string) (func(tls.ConnectionState) error, error) {
	switch fingerprint {
	case "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized":
		return nil, fmt.Errorf("`fingerprint` is used for TLS certificate pinning. If you need to specify the browser fingerprint, use `client-fingerprint`")
	}
	fingerprint = strings.TrimSpace(strings.Replace(fingerprint, ":", "", -1))
	fpByte, err := hex.DecodeString(fingerprint)
	if err != nil {
		return nil, fmt.Errorf("fingerprint string decode error: %w", err)
	}

	if len(fpByte) != 32 {
		return nil, fmt.Errorf("fingerprint string length error,need sha256 fingerprint")
	}

	return func(cs tls.ConnectionState) error {
		for _, chain := range cs.VerifiedChains {
			for _, cert := range chain {
				hash := sha256.Sum256(cert.Raw)
				if bytes.Equal(fpByte, hash[:]) {
					return nil
				}
			}
		}

		return errors.New("no matching fingerprint found in cert chain")
	}, nil
}

// CalculateFingerprint computes the SHA-256 fingerprint of the given DER-encoded certificate and returns it as a hex string.
func CalculateFingerprint(certDER []byte) string {
	hash := sha256.Sum256(certDER)
	return hex.EncodeToString(hash[:])
}
