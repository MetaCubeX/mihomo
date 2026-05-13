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

func installScriptConfig() string {
	return `client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
cipher AES-128-GCM
ignore-unknown-option block-outside-dns block-ipv6
verb 3
<ca>
` + testCert + `
</ca>
<cert>
` + testCert + `
</cert>
<key>
` + testKey + `
</key>
<tls-crypt>
-----BEGIN OpenVPN Static key V1-----
` + strings.Repeat("00", 256) + `
-----END OpenVPN Static key V1-----
</tls-crypt>
`
}

func TestParseClientConfigInstallScriptSubset(t *testing.T) {
	cfg, err := ParseClientConfig([]byte(installScriptConfig()))
	if err != nil {
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

func TestParseClientConfigRejectsUnsupportedDirective(t *testing.T) {
	_, err := ParseClientConfig([]byte(installScriptConfig() + "\ntls-auth ta.key 1\n"))
	if err == nil {
		t.Fatal("expected unsupported directive error")
	}
	if !strings.Contains(err.Error(), "unsupported openvpn directive") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseClientConfigRequiresTLSCrypt(t *testing.T) {
	raw := strings.ReplaceAll(installScriptConfig(), "<tls-crypt>\n-----BEGIN OpenVPN Static key V1-----\n"+strings.Repeat("00", 256)+"\n-----END OpenVPN Static key V1-----\n</tls-crypt>\n", "")
	_, err := ParseClientConfig([]byte(raw))
	if err == nil {
		t.Fatal("expected missing tls-crypt error")
	}
	if !strings.Contains(err.Error(), "tls-crypt") {
		t.Fatalf("unexpected error: %v", err)
	}
}
