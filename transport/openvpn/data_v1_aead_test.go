package openvpn

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
)

// These tests pin the P_DATA_V1 / P_DATA_V2 AEAD wire format against the
// OpenVPN protocol definition rather than against mihomo itself, so that a
// consistently-wrong implementation on both ends cannot pass.
//
// OpenVPN 2.x (src/openvpn/ssl.c, handle_data_channel_packet): for P_DATA_V2
// ad_start is taken *before* skipping the opcode byte, so the additional data
// is opcode|peer-id|packet-id; for P_DATA_V1 it is taken *after* skipping the
// opcode, so the additional data is the 4-byte packet-id only. SoftEther's
// OpenVPN server (Interop_OpenVPN.c) does the same for V1.

func v1TestKeys() (client, server *KeyMaterial) {
	client = &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x11}, 32),
		SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x33}, 32),
		RecvHMACKey:   bytes.Repeat([]byte{0x44}, maxHMACKeyLength),
	}
	server = &KeyMaterial{
		SendCipherKey: client.RecvCipherKey,
		SendHMACKey:   client.RecvHMACKey,
		RecvCipherKey: client.SendCipherKey,
		RecvHMACKey:   client.SendHMACKey,
	}
	return
}

// refAEAD is an independent reference implementation of the OpenVPN AEAD
// data channel: nonce = packet-id || implicit IV (first 8 bytes of the HMAC key),
// wire = header || packet-id || tag || ciphertext.
func refAEAD(t *testing.T, cipherKey, hmacKey []byte) (cipher.AEAD, func(uint32) []byte) {
	t.Helper()
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := func(pid uint32) []byte {
		n := make([]byte, 12)
		binary.BigEndian.PutUint32(n[:4], pid)
		copy(n[4:], hmacKey[:8])
		return n
	}
	return aead, nonce
}

func refSeal(t *testing.T, cipherKey, hmacKey, header []byte, pid uint32, ad, plain []byte) []byte {
	aead, nonce := refAEAD(t, cipherKey, hmacKey)
	sealed := aead.Seal(nil, nonce(pid), plain, ad)
	tagStart := len(sealed) - DataChannelTagSize
	var pidb [4]byte
	binary.BigEndian.PutUint32(pidb[:], pid)
	out := append([]byte{}, header...)
	out = append(out, pidb[:]...)
	out = append(out, sealed[tagStart:]...)
	return append(out, sealed[:tagStart]...)
}

func refOpen(t *testing.T, cipherKey, hmacKey []byte, packet []byte, headerSize int, ad []byte) ([]byte, error) {
	aead, nonce := refAEAD(t, cipherKey, hmacKey)
	pid := binary.BigEndian.Uint32(packet[headerSize : headerSize+4])
	tag := packet[headerSize+4 : headerSize+4+DataChannelTagSize]
	ct := packet[headerSize+4+DataChannelTagSize:]
	return aead.Open(nil, nonce(pid), append(append([]byte{}, ct...), tag...), ad)
}

var testIPPacket = []byte{0x45, 0, 0, 20, 1, 2, 3, 4, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1}

func TestDataChannelAESGCMV1RoundTrip(t *testing.T) {
	ck, sk := v1TestKeys()
	client, err := NewDataChannel(ck, CipherAES256GCM, AuthSHA1, PeerIDUnset, 0)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewDataChannel(sk, CipherAES256GCM, AuthSHA1, PeerIDUnset, 0)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := client.Encrypt(testIPPacket)
	if err != nil {
		t.Fatal(err)
	}
	if opcode, _ := parseOpcodeKeyID(enc[0]); opcode != PDataV1 {
		t.Fatalf("unexpected data opcode: %s", opcode)
	}
	plain, err := server.Decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, testIPPacket) {
		t.Fatalf("unexpected decrypted packet: %x", plain)
	}
}

// mihomo -> standard OpenVPN/SoftEther peer: our V1 packet must authenticate
// with AD = packet-id only, and must NOT authenticate with opcode|packet-id.
func TestDataChannelAEADV1EncryptMatchesOpenVPN(t *testing.T) {
	ck, _ := v1TestKeys()
	client, err := NewDataChannel(ck, CipherAES256GCM, AuthSHA1, PeerIDUnset, 4)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := client.Encrypt(testIPPacket)
	if err != nil {
		t.Fatal(err)
	}
	if enc[0] != 0x34 { // P_DATA_V1, key-id 4, as seen on the wire from OpenVPN 2.6
		t.Fatalf("unexpected first byte %#02x", enc[0])
	}
	pidOnly := enc[1:5]
	plain, err := refOpen(t, ck.SendCipherKey, ck.SendHMACKey, enc, 1, pidOnly)
	if err != nil {
		t.Fatalf("standard peer rejects our P_DATA_V1 packet (AD must be packet-id only): %v", err)
	}
	if !bytes.Equal(plain, testIPPacket) {
		t.Fatalf("unexpected plaintext: %x", plain)
	}
	if _, err := refOpen(t, ck.SendCipherKey, ck.SendHMACKey, enc, 1, enc[:5]); err == nil {
		t.Fatal("P_DATA_V1 must not authenticate the opcode byte")
	}
}

// standard OpenVPN/SoftEther peer -> mihomo: a V1 packet sealed with
// AD = packet-id only must decrypt.
func TestDataChannelAEADV1DecryptMatchesOpenVPN(t *testing.T) {
	ck, sk := v1TestKeys()
	client, err := NewDataChannel(ck, CipherAES256GCM, AuthSHA1, PeerIDUnset, 4)
	if err != nil {
		t.Fatal(err)
	}
	header := []byte{0x34}
	var pidb [4]byte
	binary.BigEndian.PutUint32(pidb[:], 1)
	pkt := refSeal(t, sk.SendCipherKey, sk.SendHMACKey, header, 1, pidb[:], testIPPacket)
	plain, err := client.Decrypt(pkt)
	if err != nil {
		t.Fatalf("failed to decrypt standard P_DATA_V1 packet: %v", err)
	}
	if !bytes.Equal(plain, testIPPacket) {
		t.Fatalf("unexpected plaintext: %x", plain)
	}
	// tampering with the (unauthenticated-by-AD) opcode key-id must not be
	// what makes or breaks decryption, but tampering with the packet id must.
	binary.BigEndian.PutUint32(pidb[:], 2)
	pkt = refSeal(t, sk.SendCipherKey, sk.SendHMACKey, header, 2, pidb[:], testIPPacket)
	pkt[4] ^= 0xff
	if _, err := client.Decrypt(pkt); err == nil {
		t.Fatal("expected authentication failure after packet id tamper")
	}
}

// Regression guard: P_DATA_V2 must keep authenticating opcode|peer-id|packet-id.
func TestDataChannelAEADV2StillAuthenticatesHeader(t *testing.T) {
	ck, sk := v1TestKeys()
	client, err := NewDataChannel(ck, CipherAES256GCM, AuthSHA1, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := client.Encrypt(testIPPacket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := refOpen(t, ck.SendCipherKey, ck.SendHMACKey, enc, 4, enc[:8]); err != nil {
		t.Fatalf("standard peer rejects our P_DATA_V2 packet: %v", err)
	}
	header := []byte{opcodeKeyID(PDataV2, 0), 0, 0, 7}
	var pidb [4]byte
	binary.BigEndian.PutUint32(pidb[:], 1)
	pkt := refSeal(t, sk.SendCipherKey, sk.SendHMACKey, header, 1, append(append([]byte{}, header...), pidb[:]...), testIPPacket)
	if _, err := client.Decrypt(pkt); err != nil {
		t.Fatalf("failed to decrypt standard P_DATA_V2 packet: %v", err)
	}
}
