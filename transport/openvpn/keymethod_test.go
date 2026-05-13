package openvpn

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestKeyMethod2ClientMarshalAndDerive(t *testing.T) {
	record := &KeyMethod2Record{
		Options:  InstallScriptOptionsString(ProtoUDP),
		PeerInfo: InstallScriptPeerInfo(),
	}
	for i := range record.Sources.Client.PreMaster {
		record.Sources.Client.PreMaster[i] = byte(i + 1)
	}
	for i := range record.Sources.Client.Random1 {
		record.Sources.Client.Random1[i] = byte(i + 2)
		record.Sources.Client.Random2[i] = byte(i + 3)
		record.Sources.Server.Random1[i] = byte(i + 4)
		record.Sources.Server.Random2[i] = byte(i + 5)
	}

	encoded, err := record.MarshalClient()
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(encoded[:4]) != 0 || encoded[4] != KeyMethod2 {
		t.Fatalf("unexpected key method prefix: %x", encoded[:5])
	}
	if !bytes.Contains(encoded, []byte(record.Options)) {
		t.Fatalf("encoded record is missing options")
	}

	var clientID, serverID SessionID
	copy(clientID[:], []byte("client01"))
	copy(serverID[:], []byte("server01"))
	keys, err := DeriveClientKeyMaterial(record.Sources, clientID, serverID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.SendCipherKey) != 16 || len(keys.RecvCipherKey) != 16 {
		t.Fatalf("unexpected cipher key lengths: %d/%d", len(keys.SendCipherKey), len(keys.RecvCipherKey))
	}
	if len(keys.SendHMACKey) != maxHMACKeyLength || len(keys.RecvHMACKey) != maxHMACKeyLength {
		t.Fatalf("unexpected hmac key lengths: %d/%d", len(keys.SendHMACKey), len(keys.RecvHMACKey))
	}
	if bytes.Equal(keys.SendCipherKey, keys.RecvCipherKey) {
		t.Fatalf("send and recv keys should differ")
	}
}

func TestParseServerKeyMethod2Record(t *testing.T) {
	var packet []byte
	packet = binary.BigEndian.AppendUint32(packet, 0)
	packet = append(packet, KeyMethod2)
	packet = append(packet, bytes.Repeat([]byte{1}, keySourceRandomSize)...)
	packet = append(packet, bytes.Repeat([]byte{2}, keySourceRandomSize)...)
	packet = appendOpenVPNString(packet, "server-options")
	packet = appendOpenVPNString(packet, "")
	packet = appendOpenVPNString(packet, "")
	packet = appendOpenVPNString(packet, "IV_VER=server\n")

	record, err := ParseServerKeyMethod2Record(packet)
	if err != nil {
		t.Fatal(err)
	}
	if record.Options != "server-options" || record.PeerInfo != "IV_VER=server\n" {
		t.Fatalf("unexpected parsed strings: %#v", record)
	}
	if record.Sources.Server.Random1[0] != 1 || record.Sources.Server.Random2[0] != 2 {
		t.Fatalf("unexpected server randoms")
	}
}
