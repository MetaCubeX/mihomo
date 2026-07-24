// cert_test.go —— self-test 共用:临时自签证书(127.0.0.1,ECDSA P256)。供 TLS/QUIC 两 arm 用。

package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// testCert 生成临时自签证书(127.0.0.1 + localhost,ECDSA P256,1h 有效),返回 DER + 私钥原语。
// 各测试自构 ctls.Certificate / mtls.Certificate(字段兼容:Certificate [][]byte + PrivateKey)。
// 仅 test 用;不进生产(测试密钥永不复用到生产,§6.3)。
func testCert(t *testing.T) (der []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "speedcat-test"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1).To4()},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	d, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatalf("x509 cert: %v", err)
	}
	return d, k
}
