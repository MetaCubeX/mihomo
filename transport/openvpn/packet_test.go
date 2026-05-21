package openvpn

import (
	"bytes"
	"testing"
)

func TestControlPacketEncodeDecodeWithTLSCrypt(t *testing.T) {
	cryptClient, err := NewTLSCrypt(testStaticKey(), true)
	if err != nil {
		t.Fatal(err)
	}
	cryptServer, err := NewTLSCrypt(testStaticKey(), false)
	if err != nil {
		t.Fatal(err)
	}

	var local SessionID
	copy(local[:], []byte("client01"))
	var remote SessionID
	copy(remote[:], []byte("server01"))

	packet := ControlPacket{
		Opcode:           PControlV1,
		KeyID:            0,
		LocalSession:     local,
		AckIDs:           []uint32{3, 4},
		AckRemoteSession: remote,
		MessageID:        9,
		Payload:          []byte("tls ciphertext"),
	}
	encoded, err := packet.Encode(cryptClient, 77, 1714567890)
	if err != nil {
		t.Fatal(err)
	}

	decoded, packetID, unixTime, err := DecodeControlPacket(cryptServer, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if packetID != 77 || unixTime != 1714567890 {
		t.Fatalf("unexpected tls-crypt packet id/time: %d/%d", packetID, unixTime)
	}
	if decoded.Opcode != packet.Opcode || decoded.KeyID != packet.KeyID {
		t.Fatalf("unexpected opcode/key-id: %s/%d", decoded.Opcode, decoded.KeyID)
	}
	if decoded.LocalSession != local {
		t.Fatalf("unexpected local session: %x", decoded.LocalSession)
	}
	if !bytes.Equal(decoded.Payload, packet.Payload) {
		t.Fatalf("unexpected payload: %q", decoded.Payload)
	}
	if len(decoded.AckIDs) != 2 || decoded.AckIDs[0] != 3 || decoded.AckIDs[1] != 4 {
		t.Fatalf("unexpected ack ids: %#v", decoded.AckIDs)
	}
	if decoded.AckRemoteSession != remote {
		t.Fatalf("unexpected ack remote session: %x", decoded.AckRemoteSession)
	}
}

func TestControlPacketEncodeDecodePlain(t *testing.T) {
	var local SessionID
	copy(local[:], []byte("client01"))
	var remote SessionID
	copy(remote[:], []byte("server01"))

	packet := ControlPacket{
		Opcode:           PControlV1,
		KeyID:            1,
		LocalSession:     local,
		AckIDs:           []uint32{11},
		AckRemoteSession: remote,
		MessageID:        12,
		Payload:          []byte("plain control"),
	}
	encoded, err := packet.Encode(nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	decoded, packetID, unixTime, err := DecodeControlPacket(nil, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if packetID != 0 || unixTime != 0 {
		t.Fatalf("unexpected plain packet id/time: %d/%d", packetID, unixTime)
	}
	if decoded.Opcode != packet.Opcode || decoded.KeyID != packet.KeyID {
		t.Fatalf("unexpected opcode/key-id: %s/%d", decoded.Opcode, decoded.KeyID)
	}
	if decoded.LocalSession != local {
		t.Fatalf("unexpected local session: %x", decoded.LocalSession)
	}
	if decoded.MessageID != packet.MessageID {
		t.Fatalf("unexpected message id: %d", decoded.MessageID)
	}
	if !bytes.Equal(decoded.Payload, packet.Payload) {
		t.Fatalf("unexpected payload: %q", decoded.Payload)
	}
	if len(decoded.AckIDs) != 1 || decoded.AckIDs[0] != 11 {
		t.Fatalf("unexpected ack ids: %#v", decoded.AckIDs)
	}
	if decoded.AckRemoteSession != remote {
		t.Fatalf("unexpected ack remote session: %x", decoded.AckRemoteSession)
	}
}

func TestAckPacketRejectsTrailingPayload(t *testing.T) {
	_, _, _, _, err := DecodeControlPlain(PAckV1, []byte{0, 1})
	if err == nil {
		t.Fatal("expected trailing payload error")
	}
}
