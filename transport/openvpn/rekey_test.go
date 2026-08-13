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

	err = client.renegotiate(nil)
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
	client.RotateKeyID()
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

// TestClassifyWatchAcceptsNewEpochSoftResets verifies that the soft reset
// watcher accepts a different key ID than the current epoch.
func TestClassifyWatchAcceptsNewEpochSoftResets(t *testing.T) {
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

func TestNextKeyIDFollowsOpenVPNSequence(t *testing.T) {
	// 0 -> 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 1
	got := uint8(0)
	want := []uint8{1, 2, 3, 4, 5, 6, 7, 1, 2}
	for i, w := range want {
		got = NextKeyID(got)
		if got != w {
			t.Fatalf("step %d: NextKeyID = %d, want %d", i+1, got, w)
		}
	}
}

func TestSoftResetAdvancesOpenVPNKeyID(t *testing.T) {
	clientIO, _ := newMemoryPacketPair()
	clientCrypt, err := NewTLSCrypt(testStaticKey(), true)
	if err != nil {
		t.Fatal(err)
	}
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	client := NewControlChannel(clientIO, clientCrypt, clientID)

	if client.keyID != 0 {
		t.Fatalf("initial key ID = %d; want 0", client.keyID)
	}
	client.RotateKeyID()
	if client.keyID != 1 {
		t.Fatalf("first soft reset key ID = %d; want 1", client.keyID)
	}
	client.RotateKeyID()
	if client.keyID != 2 {
		t.Fatalf("second soft reset key ID = %d; want 2", client.keyID)
	}
}

func TestRekeyDataHeaderUsesActiveKeyID(t *testing.T) {
	keys := &KeyMaterial{
		SendCipherKey: make([]byte, 16),
		SendHMACKey:   make([]byte, maxHMACKeyLength),
		RecvCipherKey: make([]byte, 16),
		RecvHMACKey:   make([]byte, maxHMACKeyLength),
	}
	for i := range keys.SendCipherKey {
		keys.SendCipherKey[i] = 0x11
		keys.RecvCipherKey[i] = 0x33
	}
	for i := range keys.SendHMACKey {
		keys.SendHMACKey[i] = 0x22
		keys.RecvHMACKey[i] = 0x44
	}

	initial, err := NewDataChannel(keys, CipherAES128GCM, AuthSHA256, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	rekeyed, err := NewDataChannel(keys, CipherAES128GCM, AuthSHA256, 7, 1)
	if err != nil {
		t.Fatal(err)
	}

	first, err := initial.Encrypt([]byte{0x45, 0, 0, 20})
	if err != nil {
		t.Fatal(err)
	}
	if _, keyID := parseOpcodeKeyID(first[0]); keyID != 0 {
		t.Fatalf("initial data packet key ID = %d; want 0", keyID)
	}

	second, err := rekeyed.Encrypt([]byte{0x45, 0, 0, 20})
	if err != nil {
		t.Fatal(err)
	}
	if _, keyID := parseOpcodeKeyID(second[0]); keyID != 1 {
		t.Fatalf("rekeyed data packet key ID = %d; want 1", keyID)
	}
}

func TestParsePushReplyAuthToken(t *testing.T) {
	msg := "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,auth-token SESS_ID_tok,auth-token-user dGVzdA=="
	reply, err := ParsePushReply(msg)
	if err != nil {
		t.Fatal(err)
	}
	user, pass, ok := reply.AuthToken()
	if !ok || pass != "SESS_ID_tok" || user != "test" {
		t.Fatalf("unexpected auth-token: user=%q pass=%q ok=%v", user, pass, ok)
	}
}

func TestStashedSoftResetIsNotSwallowedByControlRead(t *testing.T) {
	client, server := newTestChannels(t)
	client.SetRemoteSessionID(server.LocalSessionID())
	server.SetRemoteSessionID(client.LocalSessionID())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Current epoch is 1. Server starts epoch 2 while the client is still
	// reading TLS records on epoch 1.
	client.AdoptKeyID(1)
	server.AdoptKeyID(2)
	if _, err := server.Send(ctx, PControlSoftResetV1, nil); err != nil {
		t.Fatal(err)
	}

	// Ordinary Read must not deliver or drop the next-epoch soft reset.
	readCtx, readCancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer readCancel()
	if pkt, err := client.Read(readCtx); err == nil {
		t.Fatalf("Read delivered %s key=%d, want timeout", pkt.Opcode, pkt.KeyID)
	}

	got, err := client.waitForSoftReset(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Opcode != PControlSoftResetV1 || got.KeyID != 2 {
		t.Fatalf("stashed packet = %s key=%d", got.Opcode, got.KeyID)
	}
}

func TestMarkReceivedUnblocksNextEpochControl(t *testing.T) {
	client, server := newTestChannels(t)
	client.SetRemoteSessionID(server.LocalSessionID())
	server.SetRemoteSessionID(client.LocalSessionID())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Server starts a new epoch at key 1 with soft-reset message 0.
	server.AdoptKeyID(1)
	if _, err := server.Send(ctx, PControlSoftResetV1, nil); err != nil {
		t.Fatal(err)
	}
	pkt, err := client.waitForSoftReset(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.KeyID != 1 || pkt.MessageID != 0 {
		t.Fatalf("soft reset = key %d msg %d", pkt.KeyID, pkt.MessageID)
	}

	client.AdoptKeyID(1)
	client.MarkReceived(pkt.MessageID)
	client.QueueAck(pkt.MessageID)
	if err := client.SendSoftReset(ctx); err != nil {
		t.Fatal(err)
	}

	// ServerHello is new-epoch message 1. Without MarkReceived the client
	// would wait forever for message 0 and this Read would time out.
	if _, err := server.Send(ctx, PControlV1, []byte("server-hello")); err != nil {
		t.Fatal(err)
	}
	got, err := client.Read(ctx)
	if err != nil {
		t.Fatalf("client did not receive post-rekey control: %v", err)
	}
	if got.MessageID != 1 || string(got.Payload) != "server-hello" {
		t.Fatalf("unexpected packet: id=%d payload=%q", got.MessageID, got.Payload)
	}
}

func TestCaptureAuthTokenUsedOnNextKeyMethod(t *testing.T) {
	client := &Client{
		config:   &ClientConfig{Username: "orig", Password: "origpass"},
		authUser: "orig",
		authPass: "origpass",
	}
	client.captureAuthToken(&PushReply{AuthTokenUser: "test", AuthTokenPass: "SESS_ID_next"})
	if client.authUser != "test" || client.authPass != "SESS_ID_next" {
		t.Fatalf("auth credentials not refreshed: %q/%q", client.authUser, client.authPass)
	}
	if client.lastAuthToken != "SESS_ID_next" {
		t.Fatalf("lastAuthToken = %q", client.lastAuthToken)
	}
}
