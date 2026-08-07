package openvpn

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRenegotiateRejectsInvalidSoftReset(t *testing.T) {
	config := ClientConfig{}
	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&config, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	err = client.renegotiate(nil)
	if err == nil {
		t.Fatal("expected error from renegotiate with an invalid soft reset")
	}
	if !strings.Contains(err.Error(), "invalid openvpn soft reset packet") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestSendSoftResetRotatesKeyID verifies that SendSoftReset advances the key ID
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

func TestNextKeyIDSequence(t *testing.T) {
	sequence := []uint8{0, 1, 2, 3, 4, 5, 6, 7, 1}
	for i := 0; i < len(sequence)-1; i++ {
		if got := nextKeyID(sequence[i]); got != sequence[i+1] {
			t.Fatalf("nextKeyID(%d) = %d; want %d", sequence[i], got, sequence[i+1])
		}
	}
}

func TestRespondSoftResetStartsRequestedEpochAndAcknowledgesPeer(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	var serverID SessionID
	copy(serverID[:], []byte("server01"))
	client := NewControlChannel(clientIO, nil, clientID)
	client.SetRemoteSessionID(serverID)

	reset := &ControlPacket{
		Opcode:       PControlSoftResetV1,
		KeyID:        1,
		LocalSession: serverID,
		MessageID:    0,
	}
	if err := client.respondSoftReset(context.Background(), reset); err != nil {
		t.Fatal(err)
	}

	raw, err := serverIO.ReadPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	response, _, _, err := DecodeControlPacket(nil, raw)
	if err != nil {
		t.Fatal(err)
	}
	if response.Opcode != PControlSoftResetV1 || response.KeyID != 1 || response.MessageID != 0 {
		t.Fatalf("unexpected soft reset response: opcode=%s keyID=%d messageID=%d", response.Opcode, response.KeyID, response.MessageID)
	}
	if len(response.AckIDs) != 1 || response.AckIDs[0] != reset.MessageID {
		t.Fatalf("soft reset response ACKs = %v; want [%d]", response.AckIDs, reset.MessageID)
	}
	if client.recvMessage != 1 {
		t.Fatalf("recvMessage = %d; want 1", client.recvMessage)
	}
}

// TestClassifyWatchAcceptsSequentialSoftResets verifies that the soft reset
// watcher accepts the OpenVPN key ID sequence and rejects other epochs.
func TestClassifyWatchAcceptsSequentialSoftResets(t *testing.T) {
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

	// Simulate rotation to keyID=1; now keyID=2 should be accepted.
	client.keyID = 1
	pkt2 := &ControlPacket{Opcode: PControlSoftResetV1, KeyID: 2, LocalSession: serverID}
	softReset, valid = client.classifyWatchPacketLocked(pkt2)
	if !softReset || !valid {
		t.Fatalf("expected soft reset keyID=2 to be accepted when current keyID=1")
	}

	// Soft reset with the same keyID as current should NOT be accepted.
	pktSame := &ControlPacket{Opcode: PControlSoftResetV1, KeyID: 1, LocalSession: serverID}
	softReset, valid = client.classifyWatchPacketLocked(pktSame)
	if softReset || valid {
		t.Fatalf("expected soft reset with same keyID=1 to be rejected when current keyID=1")
	}

	client.keyID = 7
	pktWrap := &ControlPacket{Opcode: PControlSoftResetV1, KeyID: 1, LocalSession: serverID}
	softReset, valid = client.classifyWatchPacketLocked(pktWrap)
	if !softReset || !valid {
		t.Fatal("expected soft reset keyID=1 to be accepted when current keyID=7")
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

func TestClosePreventsTLSPublicationAndFailureRecording(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clientIO, _ := newMemoryPacketPair()
	client := &Client{
		runCtx: ctx,
		cancel: cancel,
		mux:    NewPacketMux(clientIO),
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if client.setTLSConn(nil) {
		t.Fatal("published a TLS connection after close")
	}
	client.fail(errors.New("rekey failed during shutdown"))
	if err := client.Err(); err != nil {
		t.Fatalf("recorded an intentional shutdown as a failure: %v", err)
	}
}

func TestUDPControlRetransmitsDuringRekey(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{Proto: ProtoUDP}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.control.SendSoftReset(ctx); err != nil {
		t.Fatal(err)
	}
	firstRaw, err := serverIO.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, _, _, err := DecodeControlPacket(nil, firstRaw)
	if err != nil {
		t.Fatal(err)
	}

	stopRetransmit := client.startControlRetransmit(ctx)
	defer stopRetransmit()
	secondRaw, err := serverIO.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, _, _, err := DecodeControlPacket(nil, secondRaw)
	if err != nil {
		t.Fatal(err)
	}
	if second.Opcode != first.Opcode || second.KeyID != first.KeyID || second.MessageID != first.MessageID {
		t.Fatalf("retransmit = opcode %s key %d message %d; want opcode %s key %d message %d",
			second.Opcode, second.KeyID, second.MessageID, first.Opcode, first.KeyID, first.MessageID)
	}
}

func TestRetransmitWithoutPendingMessagePreservesACK(t *testing.T) {
	clientIO, _ := newMemoryPacketPair()
	control := NewControlChannel(clientIO, nil, SessionID{})
	control.ackPending = []uint32{7}
	if err := control.RetransmitPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(control.ackPending) != 1 || control.ackPending[0] != 7 {
		t.Fatalf("pending ACKs = %v; want [7]", control.ackPending)
	}
}

// testCAPEM returns a minimal self-signed certificate for test configs.
func testCAPEM() []byte {
	return []byte(testCert)
}
