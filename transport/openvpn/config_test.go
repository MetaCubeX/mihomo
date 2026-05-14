package openvpn

import (
	"strings"
	"testing"
)

const testCert = `-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUQbG/Z7JQGg+Jb42bBYK6q8I4g5swCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHbWlob21vMB4XDTI2MDUwMTAwMDAwMFoXDTM2MDQyOTAwMDAw
MFowEjEQMA4GA1UEAwwHbWlob21vMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
hT8O8v9COiL0e7Gmab6r8jYxgB5xIvEtL10eF6QpJm+5ROK8f8yO8JHj2L2F6i1v
g7CNgMCoX9YnZ9wqOqNTMFEwHQYDVR0OBBYEFDuK1nBI7w+Kz8o9hD7UzpJkq1N2
MB8GA1UdIwQYMBaAFDuK1nBI7w+Kz8o9hD7UzpJkq1N2MA8GA1UdEwEB/wQFMAMB
Af8wCgYIKoZIzj0EAwIDSAAwRQIhAJ4mquCRw+W1M7RCNzUVpV9qPzR9qYpK4SAi
6pEh8FeaAiBKv+YbWBjjiWk0Yxch3v7y8W7S7e3pVtHh8x9n9+6w1Q==
-----END CERTIFICATE-----`

const testKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIG1paG9tb19vcGVudnBuX3Rlc3Rfa2V5XzEyMzQ1Njc4oAoGCCqGSM49
AwEHoUQDQgAEhT8O8v9COiL0e7Gmab6r8jYxgB5xIvEtL10eF6QpJm+5ROK8f8yO
8JHj2L2F6i1vg7CNgMCoX9YnZ9wqOg==
-----END EC PRIVATE KEY-----`

func testTLSCryptBlock() string {
	return `-----BEGIN OpenVPN Static key V1-----
` + strings.Repeat("00", 256) + `
-----END OpenVPN Static key V1-----`
}

func yamlStyleConfig() *ClientConfig {
	return &ClientConfig{
		RemoteHost: "vpn.example.com",
		RemotePort: 1194,
		Proto:      "udp",
		Dev:        "tun",
		Cipher:     "AES-128-GCM",
		Auth:       "SHA256",
		CA:         []byte(testCert),
		Cert:       []byte(testCert),
		Key:        []byte(testKey),
		TLSCrypt:   []byte(testTLSCryptBlock()),
	}
}

func TestClientConfigYAMLStyleInstallScriptSubset(t *testing.T) {
	cfg := yamlStyleConfig()
	if err := cfg.Prepare(); err != nil {
		t.Fatal(err)
	}
	if cfg.RemoteAddress() != "vpn.example.com:1194" {
		t.Fatalf("unexpected remote address: %s", cfg.RemoteAddress())
	}
	if cfg.Proto != ProtoUDP {
		t.Fatalf("unexpected proto: %s", cfg.Proto)
	}
	if cfg.Cipher != CipherAES128GCM || cfg.Auth != AuthSHA256 {
		t.Fatalf("unexpected crypto: %s/%s", cfg.Cipher, cfg.Auth)
	}
	if len(cfg.TLSCryptKey) != 256 {
		t.Fatalf("unexpected tls-crypt key length: %d", len(cfg.TLSCryptKey))
	}
}

func TestClientConfigDefaults(t *testing.T) {
	cfg := yamlStyleConfig()
	cfg.Proto = ""
	cfg.Dev = ""
	cfg.Cipher = ""
	cfg.Auth = ""

	if err := cfg.Prepare(); err != nil {
		t.Fatal(err)
	}
	if cfg.Proto != ProtoUDP || cfg.Dev != "tun" || cfg.Cipher != CipherAES128GCM || cfg.Auth != AuthSHA256 {
		t.Fatalf("unexpected defaults: proto=%s dev=%s cipher=%s auth=%s", cfg.Proto, cfg.Dev, cfg.Cipher, cfg.Auth)
	}
}

func TestClientConfigRejectsUnsupportedProto(t *testing.T) {
	cfg := yamlStyleConfig()
	cfg.Proto = "tcp-server"
	err := cfg.Prepare()
	if err == nil {
		t.Fatal("expected unsupported proto error")
	}
	if !strings.Contains(err.Error(), "unsupported openvpn proto") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientConfigRequiresTLSCrypt(t *testing.T) {
	cfg := yamlStyleConfig()
	cfg.TLSCrypt = nil
	err := cfg.Prepare()
	if err == nil {
		t.Fatal("expected missing tls-crypt error")
	}
	if !strings.Contains(err.Error(), "tls-crypt") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientConfigAuthUserPassAES256(t *testing.T) {
	cfg := &ClientConfig{
		RemoteHost: "vpn.example.com",
		RemotePort: 31194,
		Proto:      "udp",
		Dev:        "tun",
		Cipher:     "AES-256-GCM",
		Auth:       "SHA256",
		CA:         []byte(testCert),
		Username:   "user",
		Password:   "secret",
		TLSCrypt:   []byte(testTLSCryptBlock()),
	}
	if err := cfg.Prepare(); err != nil {
		t.Fatal(err)
	}
	if cfg.Cipher != CipherAES256GCM {
		t.Fatalf("unexpected cipher: %s", cfg.Cipher)
	}
	if cfg.DataCipherKeyLength() != 32 {
		t.Fatalf("unexpected data key length helper: %d", cfg.DataCipherKeyLength())
	}
}

func TestClientConfigRequiresAuth(t *testing.T) {
	cfg := yamlStyleConfig()
	cfg.Cert = nil
	cfg.Key = nil
	cfg.Username = ""
	err := cfg.Prepare()
	if err == nil {
		t.Fatal("expected missing auth error")
	}
	if !strings.Contains(err.Error(), "cert+key or username") {
		t.Fatalf("unexpected error: %v", err)
	}
}
