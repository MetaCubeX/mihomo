package openvpn

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDataChannelAESGCMV2RoundTrip(t *testing.T) {
	clientKeys := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x11}, 16),
		SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x33}, 16),
		RecvHMACKey:   bytes.Repeat([]byte{0x44}, maxHMACKeyLength),
	}
	serverKeys := &KeyMaterial{
		SendCipherKey: clientKeys.RecvCipherKey,
		SendHMACKey:   clientKeys.RecvHMACKey,
		RecvCipherKey: clientKeys.SendCipherKey,
		RecvHMACKey:   clientKeys.SendHMACKey,
	}
	client, err := NewDataChannel(clientKeys, CipherAES128GCM, 7)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewDataChannel(serverKeys, CipherAES128GCM, 7)
	if err != nil {
		t.Fatal(err)
	}

	ipPacket := []byte{0x45, 0, 0, 20, 1, 2, 3, 4, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1}
	encrypted, err := client.Encrypt(ipPacket)
	if err != nil {
		t.Fatal(err)
	}
	if opcode, _ := parseOpcodeKeyID(encrypted[0]); opcode != PDataV2 {
		t.Fatalf("unexpected data opcode: %s", opcode)
	}
	if packetID := binary.BigEndian.Uint32(encrypted[4:8]); packetID != 1 {
		t.Fatalf("unexpected first data packet id: %d", packetID)
	}
	plain, err := server.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, ipPacket) {
		t.Fatalf("unexpected decrypted packet: %x", plain)
	}
	encrypted[len(encrypted)-1] ^= 0xff
	if _, err := server.Decrypt(encrypted); err == nil {
		t.Fatal("expected authentication failure")
	}
	encrypted, err = client.Encrypt(ipPacket)
	if err != nil {
		t.Fatal(err)
	}
	encrypted[7] ^= 0xff
	if _, err := server.Decrypt(encrypted); err == nil {
		t.Fatal("expected authentication failure after packet id tamper")
	}
}

func TestParsePushReply(t *testing.T) {
	reply, err := ParsePushReply("PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 8.8.8.8,ifconfig 10.8.0.2 255.255.255.0,peer-id 3,block-ipv6\x00")
	if err != nil {
		t.Fatal(err)
	}
	if len(reply.Prefixes) != 1 || reply.Prefixes[0].String() != "10.8.0.2/24" {
		t.Fatalf("unexpected prefixes: %#v", reply.Prefixes)
	}
	if reply.PeerID != 3 || !reply.Redirect || !reply.BlockIPv6 {
		t.Fatalf("unexpected push flags: %#v", reply)
	}
	if len(reply.DNS) != 1 || reply.DNS[0].String() != "8.8.8.8" {
		t.Fatalf("unexpected DNS: %#v", reply.DNS)
	}
}

func TestDataChannelChaCha20Poly1305V2RoundTrip(t *testing.T) {
	clientKeys := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x11}, 32),
		SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x33}, 32),
		RecvHMACKey:   bytes.Repeat([]byte{0x44}, maxHMACKeyLength),
	}
	serverKeys := &KeyMaterial{
		SendCipherKey: clientKeys.RecvCipherKey,
		SendHMACKey:   clientKeys.RecvHMACKey,
		RecvCipherKey: clientKeys.SendCipherKey,
		RecvHMACKey:   clientKeys.SendHMACKey,
	}
	client, err := NewDataChannel(clientKeys, CipherChaCha20Poly1305, 7)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewDataChannel(serverKeys, CipherChaCha20Poly1305, 7)
	if err != nil {
		t.Fatal(err)
	}

	ipPacket := []byte{0x45, 0, 0, 20, 1, 2, 3, 4, 64, 17, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1}
	encrypted, err := client.Encrypt(ipPacket)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := server.Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, ipPacket) {
		t.Fatalf("unexpected decrypted packet: %x", plain)
	}
	encrypted[len(encrypted)-1] ^= 0xff
	if _, err := server.Decrypt(encrypted); err == nil {
		t.Fatal("expected authentication failure")
	}
}
