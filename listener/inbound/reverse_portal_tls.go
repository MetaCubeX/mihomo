package inbound

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

// buildServerTLS 为 reverse-portal 的普通 TLS 层(非 REALITY)构造 tls.Config(TLS1.3,vision 需要)。
// 提供 cert/key(PEM 文件路径或内联 PEM)则用之;否则自签一张(便于测试 / 内网信任场景)。
func buildServerTLS(certPEM, keyPEM string) (*tls.Config, error) {
	var cert tls.Certificate
	var err error
	if certPEM != "" && keyPEM != "" {
		c, cerr := readMaybeFile(certPEM)
		if cerr != nil {
			return nil, cerr
		}
		k, kerr := readMaybeFile(keyPEM)
		if kerr != nil {
			return nil, kerr
		}
		cert, err = tls.X509KeyPair(c, k)
	} else {
		cert, err = genSelfSigned()
	}
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13, // vision 读 TLS1.3 记录层,必须 1.3
	}, nil
}

// readMaybeFile:内容像 PEM 就直接用,否则当文件路径读。
func readMaybeFile(s string) ([]byte, error) {
	if len(s) > 0 && (s[0] == '-') { // "-----BEGIN..."
		return []byte(s), nil
	}
	return os.ReadFile(s)
}

func genSelfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "reverse-portal"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"reverse-portal"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
