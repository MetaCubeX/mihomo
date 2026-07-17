package openvpn

import (
	"context"
	"strings"
	"testing"
)

func testTLSCryptV2ClientBlock() string {
	return `-----BEGIN OpenVPN tls-crypt-v2 client key-----
` + strings.Repeat("aa", 256) + `
-----END OpenVPN tls-crypt-v2 client key-----`
}

func testTLSCryptV2ServerBlock() string {
	return `-----BEGIN OpenVPN tls-crypt-v2 server key-----
` + strings.Repeat("bb", 256) + `
-----END OpenVPN tls-crypt-v2 server key-----`
}

func TestDecodeTLSCryptV2ClientKey(t *testing.T) {
	key, err := DecodeTLSCryptV2ClientKey([]byte(testTLSCryptV2ClientBlock()))
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 256 {
		t.Fatalf("expected 256 bytes, got %d", len(key))
	}
	// First byte should be 0xaa (from "aa" hex)
	if key[0] != 0xaa {
		t.Fatalf("expected first byte 0xaa, got 0x%02x", key[0])
	}
}

func TestDecodeTLSCryptV2ServerKey(t *testing.T) {
	key, err := DecodeTLSCryptV2ServerKey([]byte(testTLSCryptV2ServerBlock()))
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 256 {
		t.Fatalf("expected 256 bytes, got %d", len(key))
	}
	if key[0] != 0xbb {
		t.Fatalf("expected first byte 0xbb, got 0x%02x", key[0])
	}
}

func TestTLSCryptV2ClientServerRoundTrip(t *testing.T) {
	clientKey, err := DecodeTLSCryptV2ClientKey([]byte(testTLSCryptV2ClientBlock()))
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := DecodeTLSCryptV2ServerKey([]byte(testTLSCryptV2ServerBlock()))
	if err != nil {
		t.Fatal(err)
	}

	clientCrypt, err := NewTLSCryptV2(clientKey, serverKey, true)
	if err != nil {
		t.Fatal(err)
	}
	serverCrypt, err := NewTLSCryptV2(clientKey, serverKey, false)
	if err != nil {
		t.Fatal(err)
	}

	// Client wraps, server unwraps.
	header := []byte{opcodeKeyID(PControlV1, 0), 1, 2, 3, 4, 5, 6, 7, 8}
	plaintext := []byte("hello tls-crypt-v2 world")
	wrapped, err := clientCrypt.Wrap(header, 42, 1714567890, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	gotHeader, gotPID, gotTime, gotPlain, err := serverCrypt.Unwrap(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotHeader) != string(header) {
		t.Fatalf("header mismatch: got %v, want %v", gotHeader, header)
	}
	if gotPID != 42 {
		t.Fatalf("packet ID mismatch: got %d, want 42", gotPID)
	}
	if gotTime != 1714567890 {
		t.Fatalf("unix time mismatch: got %d, want 1714567890", gotTime)
	}
	if string(gotPlain) != string(plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", gotPlain, plaintext)
	}
}

func TestTLSCryptV2ServerClientRoundTrip(t *testing.T) {
	clientKey, err := DecodeTLSCryptV2ClientKey([]byte(testTLSCryptV2ClientBlock()))
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := DecodeTLSCryptV2ServerKey([]byte(testTLSCryptV2ServerBlock()))
	if err != nil {
		t.Fatal(err)
	}

	clientCrypt, err := NewTLSCryptV2(clientKey, serverKey, true)
	if err != nil {
		t.Fatal(err)
	}
	serverCrypt, err := NewTLSCryptV2(clientKey, serverKey, false)
	if err != nil {
		t.Fatal(err)
	}

	// Server wraps, client unwraps.
	header := []byte{opcodeKeyID(PControlV1, 0), 1, 2, 3, 4, 5, 6, 7, 8}
	plaintext := []byte("server to client message")
	wrapped, err := serverCrypt.Wrap(header, 99, 1714567891, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, gotPlain, err := clientCrypt.Unwrap(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotPlain) != string(plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", gotPlain, plaintext)
	}
}

func TestTLSCryptV2RejectsTamperedPacket(t *testing.T) {
	clientKey, err := DecodeTLSCryptV2ClientKey([]byte(testTLSCryptV2ClientBlock()))
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := DecodeTLSCryptV2ServerKey([]byte(testTLSCryptV2ServerBlock()))
	if err != nil {
		t.Fatal(err)
	}

	clientCrypt, err := NewTLSCryptV2(clientKey, serverKey, true)
	if err != nil {
		t.Fatal(err)
	}
	serverCrypt, err := NewTLSCryptV2(clientKey, serverKey, false)
	if err != nil {
		t.Fatal(err)
	}

	header := []byte{opcodeKeyID(PControlV1, 0), 1, 2, 3, 4, 5, 6, 7, 8}
	plaintext := []byte("sensitive data")
	wrapped, err := clientCrypt.Wrap(header, 1, 100, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the ciphertext.
	wrapped[len(wrapped)-1] ^= 0xff

	_, _, _, _, err = serverCrypt.Unwrap(wrapped)
	if err == nil {
		t.Fatal("expected error from tampered tls-crypt-v2 packet")
	}
}

func TestTLSCryptV2RejectsWrongKey(t *testing.T) {
	// Two completely different client keys.
	clientKey1, err := DecodeTLSCryptV2ClientKey([]byte(testTLSCryptV2ClientBlock()))
	if err != nil {
		t.Fatal(err)
	}
	clientKey2 := make([]byte, 256)
	for i := range clientKey2 {
		clientKey2[i] = 0xdd
	}
	serverKey := make([]byte, 256)
	for i := range serverKey {
		serverKey[i] = 0xee
	}

	// Client uses clientKey1, server expects clientKey2.
	clientCrypt, err := NewTLSCryptV2(clientKey1, serverKey, true)
	if err != nil {
		t.Fatal(err)
	}
	serverCrypt, err := NewTLSCryptV2(clientKey2, serverKey, false)
	if err != nil {
		t.Fatal(err)
	}

	header := []byte{opcodeKeyID(PControlV1, 0), 1, 2, 3, 4, 5, 6, 7, 8}
	plaintext := []byte("test")
	wrapped, err := clientCrypt.Wrap(header, 1, 100, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, _, err = serverCrypt.Unwrap(wrapped)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong client key")
	}
}

func TestClientWithTLSCryptV2(t *testing.T) {
	config := ClientConfig{
		RemoteHost:       "1.2.3.4",
		RemotePort:       1194,
		CA:               []byte(testCert),
		Cipher:           CipherAES128GCM,
		Auth:             AuthSHA256,
		Username:         "user",
		Password:         "pass",
		TLSCryptV2Client: []byte(testTLSCryptV2ClientBlock()),
		TLSCryptV2Server: []byte(testTLSCryptV2ServerBlock()),
	}
	if err := config.Prepare(); err != nil {
		t.Fatal(err)
	}
	if len(config.TLSCryptV2ClientKey) != 256 {
		t.Fatalf("expected client key 256 bytes, got %d", len(config.TLSCryptV2ClientKey))
	}
	if len(config.TLSCryptV2ServerKey) != 256 {
		t.Fatalf("expected server key 256 bytes, got %d", len(config.TLSCryptV2ServerKey))
	}

	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&config, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Verify the control channel uses TLSCryptV2.
	if _, ok := client.control.crypt.(*TLSCryptV2); !ok {
		t.Fatalf("expected control cryptor to be *TLSCryptV2, got %T", client.control.crypt)
	}

	// Verify wrap/unwrap works through the client's cryptor.
	ctx := context.Background()
	if _, err := client.control.Send(ctx, PControlV1, []byte("test message")); err != nil {
		t.Fatal(err)
	}
}

func TestTLSCryptV2MutuallyExclusiveWithTLSCrypt(t *testing.T) {
	config := ClientConfig{
		RemoteHost:       "1.2.3.4",
		RemotePort:       1194,
		CA:               []byte(testCert),
		Cipher:           CipherAES128GCM,
		Auth:             AuthSHA256,
		Username:         "user",
		TLSCrypt:         []byte(testTLSCryptBlock()),
		TLSCryptV2Client: []byte(testTLSCryptV2ClientBlock()),
		TLSCryptV2Server: []byte(testTLSCryptV2ServerBlock()),
	}
	err := config.Prepare()
	if err == nil {
		t.Fatal("expected error when both tls-crypt and tls-crypt-v2 are set")
	}
}

func TestTLSCryptV2RequiresBothKeys(t *testing.T) {
	config := ClientConfig{
		RemoteHost:       "1.2.3.4",
		RemotePort:       1194,
		CA:               []byte(testCert),
		Cipher:           CipherAES128GCM,
		Auth:             AuthSHA256,
		Username:         "user",
		TLSCryptV2Client: []byte(testTLSCryptV2ClientBlock()),
		// Missing server key.
	}
	err := config.Prepare()
	if err == nil {
		t.Fatal("expected error when tls-crypt-v2 client key is set without server key")
	}
}
