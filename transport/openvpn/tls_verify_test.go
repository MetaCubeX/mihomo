package openvpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// generateTestCert generates a self-signed certificate for TLS verification tests.
func generateTestCert(t *testing.T, commonName string) ([]byte, *x509.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{commonName},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatal(err)
	}
	return pemBytes, cert
}

func TestParseTLSVersion(t *testing.T) {
	tests := []struct {
		input string
		want  uint16
		err   bool
	}{
		{"", 0, false},
		{"1.0", 0x0301, false},
		{"1.1", 0x0302, false},
		{"1.2", 0x0303, false},
		{"1.3", 0x0304, false},
		{"invalid", 0, true},
	}
	for _, tc := range tests {
		got, err := parseTLSVersion(tc.input)
		if tc.err {
			if err == nil {
				t.Errorf("parseTLSVersion(%q) expected error", tc.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseTLSVersion(%q) unexpected error: %v", tc.input, err)
		}
		if got != tc.want {
			t.Errorf("parseTLSVersion(%q) = 0x%04x, want 0x%04x", tc.input, got, tc.want)
		}
	}
}

func TestVerifyServerNameMatch(t *testing.T) {
	_, cert := generateTestCert(t, "vpn.example.com")
	if err := verifyServerName(cert, "vpn.example.com", "name"); err != nil {
		t.Fatalf("expected name match, got: %v", err)
	}
}

func TestVerifyServerNameMismatch(t *testing.T) {
	_, cert := generateTestCert(t, "vpn.example.com")
	err := verifyServerName(cert, "evil.com", "name")
	if err == nil {
		t.Fatal("expected error for name mismatch")
	}
}

func TestVerifyServerNamePrefixMatch(t *testing.T) {
	_, cert := generateTestCert(t, "vpn.example.com")
	if err := verifyServerName(cert, "vpn.", "name-prefix"); err != nil {
		t.Fatalf("expected name-prefix match, got: %v", err)
	}
}

func TestVerifyServerNamePrefixMismatch(t *testing.T) {
	_, cert := generateTestCert(t, "vpn.example.com")
	err := verifyServerName(cert, "evil.", "name-prefix")
	if err == nil {
		t.Fatal("expected error for name-prefix mismatch")
	}
}

func TestVerifyServerNameSubjectMatch(t *testing.T) {
	_, cert := generateTestCert(t, "vpn.example.com")
	// Subject includes CN=vpn.example.com
	err := verifyServerName(cert, cert.Subject.String(), "subject")
	if err != nil {
		t.Fatalf("expected subject match, got: %v", err)
	}
}

func TestVerifyKeyUsageMatch(t *testing.T) {
	_, cert := generateTestCert(t, "test")
	// cert has DigitalSignature | KeyEncipherment = 0x20 | 0x04 = 0x24
	// Check with mask 0x04 (KeyEncipherment)
	if err := verifyKeyUsage(cert, []uint16{0x04}); err != nil {
		t.Fatalf("expected KU match, got: %v", err)
	}
}

func TestVerifyKeyUsageMismatch(t *testing.T) {
	_, cert := generateTestCert(t, "test")
	// Check with mask 0x01 (DigitalSignature) - cert has it
	if err := verifyKeyUsage(cert, []uint16{0x01}); err != nil {
		t.Fatalf("expected KU match for DigitalSignature, got: %v", err)
	}
	// Check with mask 0x80 (CRLSign) - cert does not have it
	err := verifyKeyUsage(cert, []uint16{0x80})
	if err == nil {
		t.Fatal("expected KU mismatch for CRLSign")
	}
}

func TestVerifyEKUServer(t *testing.T) {
	_, cert := generateTestCert(t, "test")
	if err := verifyEKU(cert, "server"); err != nil {
		t.Fatalf("expected EKU server match, got: %v", err)
	}
}

func TestVerifyEKUClientMismatch(t *testing.T) {
	_, cert := generateTestCert(t, "test")
	err := verifyEKU(cert, "client")
	if err == nil {
		t.Fatal("expected EKU client mismatch")
	}
}

func TestPeerFingerprintConfig(t *testing.T) {
	caPEM, cert := generateTestCert(t, "vpn.example.com")
	fingerprint := sha256.Sum256(cert.Raw)
	fpHex := hex.EncodeToString(fingerprint[:])

	config := ClientConfig{
		RemoteHost:      "1.2.3.4",
		RemotePort:      1194,
		CA:              caPEM,
		Cipher:          CipherAES128GCM,
		Auth:            AuthSHA256,
		Username:        "user",
		PeerFingerprint: []string{fpHex},
	}
	if err := config.Prepare(); err != nil {
		t.Fatal(err)
	}

	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&config, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// The tlsConfig should be created successfully with fingerprint verification.
	// We can't do a full handshake in unit tests, but we can verify the config builds.
	_ = client
}

func TestPeerFingerprintInvalidHex(t *testing.T) {
	caPEM, _ := generateTestCert(t, "vpn.example.com")
	config := ClientConfig{
		RemoteHost:      "1.2.3.4",
		RemotePort:      1194,
		CA:              caPEM,
		Cipher:          CipherAES128GCM,
		Auth:            AuthSHA256,
		Username:        "user",
		PeerFingerprint: []string{"not-hex"},
	}
	if err := config.Prepare(); err != nil {
		t.Fatal(err)
	}
	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&config, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// tlsConfig is called lazily during handshake. Verify it fails.
	_, err = client.tlsConfig()
	if err == nil {
		t.Fatal("expected error for invalid fingerprint hex in tlsConfig")
	}
}

func TestTLSVersionConfig(t *testing.T) {
	caPEM, _ := generateTestCert(t, "vpn.example.com")
	config := ClientConfig{
		RemoteHost:     "1.2.3.4",
		RemotePort:     1194,
		CA:             caPEM,
		Cipher:         CipherAES128GCM,
		Auth:           AuthSHA256,
		Username:       "user",
		TLSVersionMin:  "1.2",
		TLSVersionMax:  "1.3",
	}
	if err := config.Prepare(); err != nil {
		t.Fatal(err)
	}
	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&config, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
}

func TestTLSVersionInvalid(t *testing.T) {
	caPEM, _ := generateTestCert(t, "vpn.example.com")
	config := ClientConfig{
		RemoteHost:    "1.2.3.4",
		RemotePort:    1194,
		CA:            caPEM,
		Cipher:        CipherAES128GCM,
		Auth:          AuthSHA256,
		Username:      "user",
		TLSVersionMin: "invalid",
	}
	if err := config.Prepare(); err != nil {
		t.Fatal(err)
	}
	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&config, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// tlsConfig is called lazily during handshake. Verify it fails.
	_, err = client.tlsConfig()
	if err == nil {
		t.Fatal("expected error for invalid TLS version in tlsConfig")
	}
}
