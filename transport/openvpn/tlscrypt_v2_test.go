package openvpn

import (
	"bytes"
	"context"
	"encoding/pem"
	"testing"
)

func testTLSCryptV2ClientPEM() []byte {
	key := make([]byte, 256)
	for i := range key {
		key[i] = byte(i)
	}
	wrapped := []byte("wrapped-client-key-fixture")
	body := append(key, wrapped...)
	return pem.EncodeToMemory(&pem.Block{Type: tlsCryptV2ClientPEMType, Bytes: body})
}

func TestDecodeTLSCryptV2ClientKey(t *testing.T) {
	key, wrapped, err := DecodeTLSCryptV2ClientKey(testTLSCryptV2ClientPEM())
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 256 || !bytes.Equal(wrapped, []byte("wrapped-client-key-fixture")) {
		t.Fatalf("decoded key=%d wrapped=%q", len(key), wrapped)
	}
}

func TestDecodeTLSCryptV2RejectsHexStaticKeyStyle(t *testing.T) {
	_, _, err := DecodeTLSCryptV2ClientKey([]byte("-----BEGIN OpenVPN tls-crypt-v2 client key-----\n" +
		"aaaaaaaa\n-----END OpenVPN tls-crypt-v2 client key-----\n"))
	if err == nil {
		t.Fatal("expected invalid PEM/base64 rejection")
	}
}

func TestTLSCryptV2UsesClientMaterialForControlProtection(t *testing.T) {
	key, wrapped, err := DecodeTLSCryptV2ClientKey(testTLSCryptV2ClientPEM())
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewTLSCryptV2(key, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewTLSCrypt(key, false)
	if err != nil {
		t.Fatal(err)
	}
	header := []byte{opcodeKeyID(PControlHardResetClientV3, 0), 1, 2, 3, 4, 5, 6, 7, 8}
	plain := []byte("control payload")
	encoded, err := client.Wrap(header, 0x0f000001, 1714567890, plain)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, decoded, err := server.Unwrap(encoded)
	if err != nil || !bytes.Equal(decoded, plain) {
		t.Fatalf("decoded=%q err=%v", decoded, err)
	}
}

func TestTLSCryptV2SendResetUsesV3AndAppendsWrappedKey(t *testing.T) {
	key, wrapped, err := DecodeTLSCryptV2ClientKey(testTLSCryptV2ClientPEM())
	if err != nil {
		t.Fatal(err)
	}
	crypt, err := NewTLSCryptV2(key, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	clientIO, serverIO := newMemoryPacketPair()
	var session SessionID
	copy(session[:], []byte("client01"))
	channel := NewControlChannel(clientIO, crypt, session)
	if err := channel.SendReset(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err := serverIO.ReadPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if Opcode(raw[0]>>OpcodeShift) != PControlHardResetClientV3 {
		t.Fatalf("expected V3 opcode, got %d", raw[0]>>OpcodeShift)
	}
	if !bytes.HasSuffix(raw, wrapped) {
		t.Fatal("initial V3 reset missing wrapped client key")
	}
	protected := raw[:len(raw)-len(wrapped)]
	serverCrypt, _ := NewTLSCrypt(key, false)
	packet, _, _, err := DecodeControlPacket(serverCrypt, protected)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Opcode != PControlHardResetClientV3 || packet.MessageID != 0 {
		t.Fatalf("unexpected packet: %s/%d", packet.Opcode, packet.MessageID)
	}
}

func TestClientWithTLSCryptV2(t *testing.T) {
	config := ClientConfig{
		RemoteHost: "1.2.3.4", RemotePort: 1194,
		CA: []byte(testCert), Cipher: CipherAES128GCM, Auth: AuthSHA256,
		Username: "user", Password: "pass", TLSCryptV2: testTLSCryptV2ClientPEM(),
	}
	if err := config.Prepare(); err != nil {
		t.Fatal(err)
	}
	if len(config.TLSCryptV2Key) != 256 || len(config.TLSCryptV2WrappedKey) == 0 {
		t.Fatal("v2 material not prepared")
	}
	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&config, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, ok := client.control.crypt.(*TLSCryptV2); !ok {
		t.Fatalf("wrong cryptor: %T", client.control.crypt)
	}
}

func TestTLSCryptV2MutuallyExclusiveWithTLSCrypt(t *testing.T) {
	config := ClientConfig{
		RemoteHost: "1.2.3.4", RemotePort: 1194, CA: []byte(testCert),
		Cipher: CipherAES128GCM, Auth: AuthSHA256, Username: "user",
		TLSCrypt: []byte(testTLSCryptBlock()), TLSCryptV2: testTLSCryptV2ClientPEM(),
	}
	if err := config.Prepare(); err == nil {
		t.Fatal("expected mutual exclusion error")
	}
}
