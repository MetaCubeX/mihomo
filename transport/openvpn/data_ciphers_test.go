package openvpn

import (
	"testing"
)

func TestNegotiateCipherNoPushUsesConfigured(t *testing.T) {
	cfg := ClientConfig{Cipher: CipherAES128GCM}
	got, err := cfg.NegotiateCipher(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != CipherAES128GCM {
		t.Fatalf("expected %s, got %s", CipherAES128GCM, got)
	}
}

func TestNegotiateCipherIntersection(t *testing.T) {
	cfg := ClientConfig{
		Cipher:      CipherAES128GCM,
		DataCiphers: []string{CipherAES256GCM, CipherAES128GCM},
	}
	// Server pushes AES-128-GCM and AES-256-GCM; client prefers AES-256-GCM first.
	// The first server cipher that appears in the client list should win.
	got, err := cfg.NegotiateCipher([]string{CipherAES128GCM, CipherAES256GCM}, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != CipherAES128GCM {
		t.Fatalf("expected %s (first server cipher in client list), got %s", CipherAES128GCM, got)
	}
}

func TestNegotiateCipherNoIntersectionUsesFallback(t *testing.T) {
	cfg := ClientConfig{
		Cipher:         CipherAES128GCM,
		DataCiphers:    []string{CipherAES256GCM},
		FallbackCipher: CipherAES128CBC,
	}
	// Server only has ChaCha20, client only has AES-256-GCM -> no intersection.
	got, err := cfg.NegotiateCipher([]string{CipherChaCha20Poly1305}, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != CipherAES128CBC {
		t.Fatalf("expected fallback %s, got %s", CipherAES128CBC, got)
	}
}

func TestNegotiateCipherNoIntersectionNoFallbackError(t *testing.T) {
	cfg := ClientConfig{
		Cipher:      CipherAES128GCM,
		DataCiphers: []string{CipherAES256GCM},
	}
	_, err := cfg.NegotiateCipher([]string{CipherChaCha20Poly1305}, "")
	if err == nil {
		t.Fatal("expected error when no common cipher and no fallback")
	}
}

func TestNegotiateCipherLegacySingleCipherPush(t *testing.T) {
	cfg := ClientConfig{
		Cipher: CipherAES128GCM,
	}
	// Server pushes a single legacy cipher that matches.
	got, err := cfg.NegotiateCipher(nil, CipherAES128GCM)
	if err != nil {
		t.Fatal(err)
	}
	if got != CipherAES128GCM {
		t.Fatalf("expected %s, got %s", CipherAES128GCM, got)
	}
}

func TestNegotiateCipherServerPushesDifferentCipherAccepted(t *testing.T) {
	cfg := ClientConfig{
		Cipher: CipherAES128GCM,
	}
	// Server pushes AES-256-GCM, client default is AES-128-GCM.
	// Without DataCiphers list, the pushed cipher is accepted if supported.
	got, err := cfg.NegotiateCipher(nil, CipherAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	if got != CipherAES256GCM {
		t.Fatalf("expected server-pushed %s, got %s", CipherAES256GCM, got)
	}
}

func TestParsePushReplyDataCiphers(t *testing.T) {
	msg := "PUSH_REPLY,data-ciphers AES-256-GCM:AES-128-GCM,ifconfig 10.8.0.2 255.255.255.0"
	reply, err := ParsePushReply(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply.DataCiphers) != 2 {
		t.Fatalf("expected 2 data ciphers, got %d", len(reply.DataCiphers))
	}
	if reply.DataCiphers[0] != "AES-256-GCM" {
		t.Fatalf("expected first cipher AES-256-GCM, got %s", reply.DataCiphers[0])
	}
	if reply.DataCiphers[1] != "AES-128-GCM" {
		t.Fatalf("expected second cipher AES-128-GCM, got %s", reply.DataCiphers[1])
	}
}

func TestParsePushReplyLegacyCipher(t *testing.T) {
	msg := "PUSH_REPLY,cipher AES-256-GCM,ifconfig 10.8.0.2 255.255.255.0"
	reply, err := ParsePushReply(msg)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Cipher != "AES-256-GCM" {
		t.Fatalf("expected cipher AES-256-GCM, got %s", reply.Cipher)
	}
}

func TestParsePushReplyNcpCiphers(t *testing.T) {
	msg := "PUSH_REPLY,ncp-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305,ifconfig 10.8.0.2 255.255.255.0"
	reply, err := ParsePushReply(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply.DataCiphers) != 3 {
		t.Fatalf("expected 3 data ciphers, got %d", len(reply.DataCiphers))
	}
	if reply.DataCiphers[2] != "CHACHA20-POLY1305" {
		t.Fatalf("expected third cipher CHACHA20-POLY1305, got %s", reply.DataCiphers[2])
	}
}

func TestInstallScriptPeerInfoWithDataCiphers(t *testing.T) {
	info := InstallScriptPeerInfo(CipherAES128GCM, []string{CipherAES256GCM, CipherAES128GCM, CipherChaCha20Poly1305}, "", nil)
	want := "IV_VER=mihomo-openvpn\nIV_PROTO=6\nIV_CIPHERS=AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\n"
	if info != want {
		t.Fatalf("unexpected peer-info:\n got %q\nwant %q", info, want)
	}
}
