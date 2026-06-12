package openvpn

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestClientWriteIPPacketDoesNotWaitForContextDeadline(t *testing.T) {
	clientIO, peerIO := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{Cipher: CipherAES128GCM, Auth: AuthSHA256}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	clientKeys := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x11}, 16),
		SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x33}, 16),
		RecvHMACKey:   bytes.Repeat([]byte{0x44}, maxHMACKeyLength),
	}
	client.data, err = NewDataChannel(clientKeys, CipherAES128GCM, AuthSHA256, 7)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := client.WriteIPPacket(ctx, []byte{0x45, 0, 0, 20}); err != nil {
		t.Fatal(err)
	}
	packet, err := peerIO.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) == 0 {
		t.Fatal("expected encrypted packet")
	}
}
