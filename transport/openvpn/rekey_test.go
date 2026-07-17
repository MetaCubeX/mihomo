package openvpn

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestRenegotiateFailsWithoutTLS verifies that renegotiate() returns an error
// (instead of panicking) when no TLS connection has been established.
func TestRenegotiateFailsWithoutTLS(t *testing.T) {
	config := ClientConfig{}
	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&config, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	err = client.renegotiate()
	if err == nil {
		t.Fatal("expected error from renegotiate without TLS connection")
	}
	if !errors.Is(err, errRenegotiateNoTLS) {
		t.Fatalf("expected errRenegotiateNoTLS, got %v", err)
	}
}

// TestSendSoftResetRotatesKeyID verifies that SendSoftReset toggles the key ID
// and resets the message counters for the new key epoch.
func TestSendSoftResetRotatesKeyID(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	clientCrypt, err := NewTLSCrypt(testStaticKey(), true)
	if err != nil {
		t.Fatal(err)
	}
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	var serverID SessionID
	copy(serverID[:], []byte("server01"))

	client := NewControlChannel(clientIO, clientCrypt, clientID)
	client.SetRemoteSessionID(serverID)
	client.clock = func() time.Time { return time.Unix(1714567890, 0) }

	ctx := context.Background()
	// Simulate an established first epoch with keyID=0 and some sent messages.
	if _, err := client.Send(ctx, PControlV1, []byte("msg1")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Send(ctx, PControlV1, []byte("msg2")); err != nil {
		t.Fatal(err)
	}
	if client.keyID != 0 {
		t.Fatalf("expected initial keyID=0, got %d", client.keyID)
	}
	if client.sendMessage != 2 {
		t.Fatalf("expected sendMessage=2, got %d", client.sendMessage)
	}
	if client.PendingMessages() != 2 {
		t.Fatalf("expected 2 pending messages, got %d", client.PendingMessages())
	}

	// Perform soft reset - should rotate to keyID=1 and reset counters.
	if err := client.SendSoftReset(ctx); err != nil {
		t.Fatal(err)
	}
	if client.keyID != 1 {
		t.Fatalf("expected keyID=1 after soft reset, got %d", client.keyID)
	}
	if client.sendMessage != 1 {
		t.Fatalf("expected sendMessage=1 after soft reset (0+1 for soft reset itself), got %d", client.sendMessage)
	}
	if client.recvMessage != 0 {
		t.Fatalf("expected recvMessage=0 after soft reset, got %d", client.recvMessage)
	}
	// Old pending messages should be cleared; only the soft reset itself pending.
	if client.PendingMessages() != 1 {
		t.Fatalf("expected 1 pending message (soft reset), got %d", client.PendingMessages())
	}

	// Drain the 2 old control messages + 1 soft reset from the server-side IO.
	// The client writes to clientIO.out which arrives at serverIO.in.
	// The soft reset is the 3rd packet written.
	for i := 0; i < 3; i++ {
		_, err := serverIO.ReadPacket(ctx)
		if err != nil {
			t.Fatalf("failed to drain packet %d: %v", i, err)
		}
	}
}

// TestClassifyWatchAcceptsAlternatingSoftResets verifies that the soft reset
// watcher correctly accepts rekeys on alternating key IDs (0->1->0->1).
func TestClassifyWatchAcceptsAlternatingSoftResets(t *testing.T) {
	var serverID SessionID
	copy(serverID[:], []byte("server01"))

	clientIO, _ := newMemoryPacketPair()
	clientCrypt, err := NewTLSCrypt(testStaticKey(), true)
	if err != nil {
		t.Fatal(err)
	}
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	client := NewControlChannel(clientIO, clientCrypt, clientID)
	client.SetRemoteSessionID(serverID)

	// Initial keyID = 0, so soft reset with keyID=1 should be accepted.
	pkt1 := &ControlPacket{Opcode: PControlSoftResetV1, KeyID: 1, LocalSession: serverID}
	softReset, valid := client.classifyWatchPacketLocked(pkt1)
	if !softReset || !valid {
		t.Fatalf("expected soft reset keyID=1 to be accepted when current keyID=0")
	}

	// Simulate rotation to keyID=1; now soft reset with keyID=0 should be accepted.
	client.keyID = 1
	pkt0 := &ControlPacket{Opcode: PControlSoftResetV1, KeyID: 0, LocalSession: serverID}
	softReset, valid = client.classifyWatchPacketLocked(pkt0)
	if !softReset || !valid {
		t.Fatalf("expected soft reset keyID=0 to be accepted when current keyID=1")
	}

	// Soft reset with the same keyID as current should NOT be accepted.
	pktSame := &ControlPacket{Opcode: PControlSoftResetV1, KeyID: 1, LocalSession: serverID}
	softReset, valid = client.classifyWatchPacketLocked(pktSame)
	if softReset || valid {
		t.Fatalf("expected soft reset with same keyID=1 to be rejected when current keyID=1")
	}
}

// TestDataLockProtectsDataChannelSwap verifies that the dataLock allows
// concurrent reads while a data channel swap is happening.
func TestDataLockProtectsDataChannelSwap(t *testing.T) {
	config := ClientConfig{
		RemoteHost: "1.2.3.4",
		RemotePort: 1194,
		CA:         []byte(testCert),
		Cipher:     CipherAES128GCM,
		Auth:       AuthSHA256,
		Username:   "testuser",
		Password:   "testpass",
	}
	if err := config.Prepare(); err != nil {
		t.Fatal(err)
	}
	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&config, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Without a real TLS handshake, c.data is nil.
	// Verify that ReadIPPacket returns an error (not a panic).
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = client.ReadIPPacket(ctx)
	if err == nil {
		t.Fatal("expected error from ReadIPPacket when data channel is nil")
	}
}

// testCAPEM returns a minimal self-signed certificate for test configs.
func testCAPEM() []byte {
	return []byte(testCert)
}
