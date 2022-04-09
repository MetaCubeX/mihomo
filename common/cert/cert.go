package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

var currentSerialNumber = time.Now().Unix()

type Config struct {
	ca           *x509.Certificate
	caPrivateKey *rsa.PrivateKey

	roots *x509.CertPool

	privateKey *rsa.PrivateKey

	validity     time.Duration
	keyID        []byte
	organization string

	certsStorage CertsStorage
}

type CertsStorage interface {
	Get(key string) (*tls.Certificate, bool)

	Set(key string, cert *tls.Certificate)
}

func NewAuthority(name, organization string, validity time.Duration) (*x509.Certificate, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	pub := privateKey.Public()

	pkixPub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	h := sha1.New()
	_, err = h.Write(pkixPub)
	if err != nil {
		return nil, nil, err
	}
	keyID := h.Sum(nil)

	serial := atomic.AddInt64(&currentSerialNumber, 1)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{organization},
		},
		SubjectKeyId:          keyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-validity),
		NotAfter:              time.Now().Add(validity),
		DNSNames:              []string{name},
		IsCA:                  true,
	}

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, privateKey)
	if err != nil {
		return nil, nil, err
	}

	x509c, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, err
	}

	return x509c, privateKey, nil
}

func NewConfig(ca *x509.Certificate, caPrivateKey *rsa.PrivateKey) (*Config, error) {
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pub := privateKey.Public()

	pkixPub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	h := sha1.New()
	_, err = h.Write(pkixPub)
	if err != nil {
		return nil, err
	}
	keyID := h.Sum(nil)

	return &Config{
		ca:           ca,
		caPrivateKey: caPrivateKey,
		privateKey:   privateKey,
		keyID:        keyID,
		validity:     time.Hour,
		organization: "Clash",
		certsStorage: NewDomainTrieCertsStorage(),
		roots:        roots,
	}, nil
}

func (c *Config) GetCA() *x509.Certificate {
	return c.ca
}

func (c *Config) SetOrganization(organization string) {
	c.organization = organization
}

func (c *Config) SetValidity(validity time.Duration) {
	c.validity = validity
}

func (c *Config) NewTLSConfigForHost(hostname string) *tls.Config {
	tlsConfig := &tls.Config{
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := clientHello.ServerName
			if host == "" {
				host = hostname
			}

			return c.GetOrCreateCert(host)
		},
		NextProtos: []string{"http/1.1"},
	}

	tlsConfig.InsecureSkipVerify = true

	return tlsConfig
}

func (c *Config) GetOrCreateCert(hostname string, ips ...net.IP) (*tls.Certificate, error) {
	var leaf *x509.Certificate
	tlsCertificate, ok := c.certsStorage.Get(hostname)
	if ok {
		leaf = tlsCertificate.Leaf
		if _, err := leaf.Verify(x509.VerifyOptions{
			DNSName: hostname,
			Roots:   c.roots,
		}); err == nil {
			return tlsCertificate, nil
		}
	}

	var (
		key          = hostname
		topHost      = hostname
		wildcardHost = "*." + hostname
		dnsNames     []string
	)

	if ip := net.ParseIP(hostname); ip != nil {
		ips = append(ips, ip)
	} else {
		parts := strings.Split(hostname, ".")
		l := len(parts)

		if leaf != nil {
			dnsNames = append(dnsNames, leaf.DNSNames...)
		}

		if l > 2 {
			topIndex := l - 2
			topHost = strings.Join(parts[topIndex:], ".")

			for i := topIndex; i > 0; i-- {
				wildcardHost = "*." + strings.Join(parts[i:], ".")

				if i == topIndex && (len(dnsNames) == 0 || dnsNames[0] != topHost) {
					dnsNames = append(dnsNames, topHost, wildcardHost)
				} else if !hasDnsNames(dnsNames, wildcardHost) {
					dnsNames = append(dnsNames, wildcardHost)
				}
			}
		} else {
			dnsNames = append(dnsNames, topHost, wildcardHost)
		}

		key = "+." + topHost
	}

	serial := atomic.AddInt64(&currentSerialNumber, 1)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:   topHost,
			Organization: []string{c.organization},
		},
		SubjectKeyId:          c.keyID,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             time.Now().Add(-c.validity),
		NotAfter:              time.Now().Add(c.validity),
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	raw, err := x509.CreateCertificate(rand.Reader, tmpl, c.ca, c.privateKey.Public(), c.caPrivateKey)
	if err != nil {
		return nil, err
	}

	x509c, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}

	tlsCertificate = &tls.Certificate{
		Certificate: [][]byte{raw, c.ca.Raw},
		PrivateKey:  c.privateKey,
		Leaf:        x509c,
	}

	c.certsStorage.Set(key, tlsCertificate)
	return tlsCertificate, nil
}

// GenerateAndSave generate CA private key and CA certificate and dump them to file
func GenerateAndSave(caPath string, caKeyPath string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Country:      []string{"US"},
			CommonName:   "Clash Root CA",
			Organization: []string{"Clash Trust Services"},
		},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:             time.Now().Add(-(time.Hour * 24 * 60)),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 25),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caRaw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, privateKey.Public(), privateKey)
	if err != nil {
		return err
	}

	caOut, err := os.OpenFile(caPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func(caOut *os.File) {
		_ = caOut.Close()
	}(caOut)

	if err = pem.Encode(caOut, &pem.Block{Type: "CERTIFICATE", Bytes: caRaw}); err != nil {
		return err
	}

	caKeyOut, err := os.OpenFile(caKeyPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func(caKeyOut *os.File) {
		_ = caKeyOut.Close()
	}(caKeyOut)

	if err = pem.Encode(caKeyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}); err != nil {
		return err
	}

	return nil
}

func hasDnsNames(dnsNames []string, hostname string) bool {
	for _, name := range dnsNames {
		if name == hostname {
			return true
		}
	}
	return false
}
