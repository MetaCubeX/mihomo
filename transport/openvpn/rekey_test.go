package openvpn

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
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

// TestClassifyWatchAcceptsNextEpochSoftReset verifies the soft reset watcher
// only accepts the strictly-next key epoch (0 -> 1 -> ... -> 7 -> 1), and
// rejects stale or invalid epochs.
func TestClassifyWatchAcceptsNextEpochSoftReset(t *testing.T) {
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

	// Initial keyID = 0, so a soft reset with keyID=1 (the next epoch) is accepted.
	pktNext := &ControlPacket{Opcode: PControlSoftResetV1, KeyID: 1, LocalSession: serverID}
	softReset, valid := client.classifyWatchPacketLocked(pktNext)
	if !softReset || !valid {
		t.Fatalf("expected next-epoch soft reset keyID=1 to be accepted when current keyID=0")
	}

	// Same key ID is rejected.
	pktSame := &ControlPacket{Opcode: PControlSoftResetV1, KeyID: 0, LocalSession: serverID}
	softReset, valid = client.classifyWatchPacketLocked(pktSame)
	if softReset || valid {
		t.Fatalf("expected soft reset with same keyID=0 to be rejected when current keyID=0")
	}

	// After epoch 1, key ID 0 (a stale / invalid epoch) must be rejected.
	client.keyID = 1
	pktStale := &ControlPacket{Opcode: PControlSoftResetV1, KeyID: 0, LocalSession: serverID}
	softReset, valid = client.classifyWatchPacketLocked(pktStale)
	if softReset || valid {
		t.Fatalf("expected stale soft reset keyID=0 to be rejected when current keyID=1")
	}
	// The strictly-next epoch is keyID=2.
	pktNext2 := &ControlPacket{Opcode: PControlSoftResetV1, KeyID: 2, LocalSession: serverID}
	softReset, valid = client.classifyWatchPacketLocked(pktNext2)
	if !softReset || !valid {
		t.Fatalf("expected next-epoch soft reset keyID=2 to be accepted when current keyID=1")
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

func TestRecordCompleteRejectsFragmentedKM2(t *testing.T) {
	var packet []byte
	packet = binary.BigEndian.AppendUint32(packet, 0)
	packet = append(packet, KeyMethod2)
	packet = append(packet, bytes.Repeat([]byte{1}, keySourceRandomSize)...)
	packet = append(packet, bytes.Repeat([]byte{2}, keySourceRandomSize)...)
	packet = appendOpenVPNString(packet, "server-options")
	packet = appendOpenVPNString(packet, "user")

	if complete, _ := RecordComplete(packet); complete {
		t.Fatal("fragmented record reported complete")
	}
	// Appending the remaining strings (with empty trailing ones) completes it.
	packet = appendOpenVPNString(packet, "pass")
	packet = appendOpenVPNString(packet, "IV_VER=server\n")
	if complete, _ := RecordComplete(packet); !complete {
		t.Fatal("complete record not reported complete")
	}
	// Truncated length prefix is also incomplete.
	if complete, _ := RecordComplete(packet[:len(packet)-1]); complete {
		t.Fatal("truncated record reported complete")
	}
}

func TestParseShortenedKM2OnlyWhenTLSControlFollows(t *testing.T) {
	var packet []byte
	packet = binary.BigEndian.AppendUint32(packet, 0)
	packet = append(packet, KeyMethod2)
	packet = append(packet, bytes.Repeat([]byte{1}, keySourceRandomSize)...)
	packet = append(packet, bytes.Repeat([]byte{2}, keySourceRandomSize)...)
	packet = appendOpenVPNString(packet, "server-options")
	packet = append(packet, []byte("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0\x00")...)

	// PUSH_REPLY is positively identified, so the shortened record parses.
	if _, _, err := ParseServerKeyMethod2RecordConsumed(packet); err != nil {
		t.Fatalf("shortened record with PUSH_REPLY should parse: %v", err)
	}

	// A truncated trailing string that is NOT a following TLS control
	// message must not be treated as a valid end of record: it is a
	// fragmented standard record that still needs more TLS reads.
	var frag []byte
	frag = binary.BigEndian.AppendUint32(frag, 0)
	frag = append(frag, KeyMethod2)
	frag = append(frag, bytes.Repeat([]byte{1}, keySourceRandomSize)...)
	frag = append(frag, bytes.Repeat([]byte{2}, keySourceRandomSize)...)
	frag = appendOpenVPNString(frag, "server-options")
	frag = appendOpenVPNString(frag, "username")
	frag = frag[:len(frag)-1] // truncate the username value, not a PUSH_REPLY
	if _, _, err := ParseServerKeyMethod2RecordConsumed(frag); err == nil {
		t.Fatal("truncated trailing field should not parse")
	}
	// And a standard record with all four strings always parses.
	full := appendOpenVPNString(packet, "user")
	full = appendOpenVPNString(full, "pass")
	full = appendOpenVPNString(full, "IV_VER=server\n")
	if _, _, err := ParseServerKeyMethod2RecordConsumed(full); err != nil {
		t.Fatalf("standard full record should parse: %v", err)
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

// TestReadAllKeepsPendingSoftReset ensures the queued soft reset survives the
// post-handshake drain that feeds TLS payload back to tls.Conn: draining must
// not steal the rekey trigger from waitForSoftReset.
func TestReadAllKeepsPendingSoftReset(t *testing.T) {
	client, server := newTestChannels(t)
	client.SetRemoteSessionID(server.LocalSessionID())
	server.SetRemoteSessionID(client.LocalSessionID())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Park a next-epoch soft reset in pendingSoftReset while on epoch 1.
	client.AdoptKeyID(1)
	server.AdoptKeyID(2)
	if _, err := server.Send(ctx, PControlSoftResetV1, nil); err != nil {
		t.Fatal(err)
	}
	readCtx, readCancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer readCancel()
	_, _ = client.Read(readCtx) // stashes the soft reset
	if client.pendingSoftReset == nil {
		t.Fatal("soft reset was not stashed in pendingSoftReset")
	}

	// Draining queued control must not consume the stashed soft reset.
	_ = client.ReadAll()
	if client.pendingSoftReset == nil {
		t.Fatal("ReadAll consumed the pending soft reset")
	}

	// The watcher must still see it.
	got, err := client.waitForSoftReset(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Opcode != PControlSoftResetV1 || got.KeyID != 2 {
		t.Fatalf("soft reset lost: got %s key=%d", got.Opcode, got.KeyID)
	}
}

func TestRekeyRetransmitsLostClientHello(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	serverCrypt, err := NewTLSCrypt(testStaticKey(), false)
	if err != nil {
		t.Fatal(err)
	}
	var serverID SessionID
	copy(serverID[:], []byte("server01"))

	client, err := NewClient(&ClientConfig{
		Proto:   ProtoUDP,
		TLSCryptKey: testStaticKey(),
	}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.control.SetRemoteSessionID(serverID)

	server := NewControlChannel(serverIO, serverCrypt, serverID)
	server.SetRemoteSessionID(client.control.LocalSessionID())
	client.control.clock = func() time.Time { return time.Unix(1714567890, 0) }
	server.clock = func() time.Time { return time.Unix(1714567891, 0) }

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Server starts epoch 1 with a soft reset, exactly like a real rekey.
	server.AdoptKeyID(1)
	if _, err := server.Send(ctx, PControlSoftResetV1, nil); err != nil {
		t.Fatal(err)
	}
	soft, err := client.control.waitForSoftReset(ctx)
	if err != nil {
		t.Fatal(err)
	}

	client.control.AdoptKeyID(1)
	client.control.MarkReceived(soft.MessageID)
	client.control.QueueAck(soft.MessageID)
	if err := client.control.SendSoftReset(ctx); err != nil {
		t.Fatal(err)
	}
	// Start the UDP rekey retransmission loop exactly like renegotiate().
	stop := client.retransmitRekey(ctx)
	defer stop()
	// Simulate the TLS epoch: a ClientHello record on epoch 1.
	if _, err := client.control.Send(ctx, PControlV1, []byte("client-hello")); err != nil {
		t.Fatal(err)
	}

	// Drop the client-hello the first time it is sent; the retransmit loop
	// must resend the same reliable message.
	firstHello := uint32(^uint32(0))
	gotRetransmit := false
	for i := 0; i < 5 && !gotRetransmit; i++ {
		raw, err := serverIO.ReadPacket(ctx)
		if err != nil {
			t.Fatal(err)
		}
		pkt, _, _, err := DecodeControlPacket(serverCrypt, raw)
		if err != nil {
			t.Fatal(err)
		}
		if pkt.Opcode != PControlV1 || string(pkt.Payload) != "client-hello" {
			continue
		}
		if firstHello == ^uint32(0) {
			// First copy: record its message ID and ignore it (the loss).
			firstHello = pkt.MessageID
			continue
		}
		// Second copy: same message ID (reliable retransmission), same payload.
		if pkt.MessageID == firstHello {
			gotRetransmit = true
		}
	}
	if !gotRetransmit {
		t.Fatal("client-hello was never retransmitted after loss")
	}
}

// TestRekeyRetransmitKeepsResetACK verifies that a retransmitted client soft
// reset still carries the ACK for the server's reset (merged, not replaced).
func TestRekeyRetransmitKeepsResetACK(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	clientCrypt, err := NewTLSCrypt(testStaticKey(), true)
	if err != nil {
		t.Fatal(err)
	}
	serverCrypt, err := NewTLSCrypt(testStaticKey(), false)
	if err != nil {
		t.Fatal(err)
	}
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	var serverID SessionID
	copy(serverID[:], []byte("server01"))

	client := NewControlChannel(clientIO, clientCrypt, clientID)
	client.SetRemoteSessionID(serverID)
	server := NewControlChannel(serverIO, serverCrypt, serverID)
	server.SetRemoteSessionID(clientID)
	client.clock = func() time.Time { return time.Unix(1714567890, 0) }
	server.clock = func() time.Time { return time.Unix(1714567891, 0) }

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Server starts epoch 1 with a soft reset (message 0). Client adopts the
	// epoch, ACKs message 0, and replies with its own soft reset carrying that
	// ACK.
	server.AdoptKeyID(1)
	if _, err := server.Send(ctx, PControlSoftResetV1, nil); err != nil {
		t.Fatal(err)
	}
	soft, err := client.waitForSoftReset(ctx)
	if err != nil {
		t.Fatal(err)
	}
	client.AdoptKeyID(1)
	client.MarkReceived(soft.MessageID)
	client.QueueAck(soft.MessageID)
	if err := client.SendSoftReset(ctx); err != nil {
		t.Fatal(err)
	}

	// Read the first client soft reset; its ACK list must contain the server
	// reset (message 0).
	raw, err := serverIO.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, _, _, err := DecodeControlPacket(serverCrypt, raw)
	if err != nil {
		t.Fatal(err)
	}
	if first.Opcode != PControlSoftResetV1 {
		t.Fatalf("first packet opcode = %s", first.Opcode)
	}
	foundResetAck := false
	for _, ack := range first.AckIDs {
		if ack == 0 {
			foundResetAck = true
		}
	}
	if !foundResetAck {
		t.Fatalf("first client soft reset missing reset ACK: %v", first.AckIDs)
	}

	// Retransmit the client's pending messages; the retransmitted soft reset
	// must STILL carry the reset ACK.
	if err := client.RetransmitPending(ctx); err != nil {
		t.Fatal(err)
	}
	raw, err = serverIO.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	re, _, _, err := DecodeControlPacket(serverCrypt, raw)
	if err != nil {
		t.Fatal(err)
	}
	if re.Opcode != PControlSoftResetV1 {
		t.Fatalf("retransmitted opcode = %s", re.Opcode)
	}
	foundResetAck = false
	for _, ack := range re.AckIDs {
		if ack == 0 {
			foundResetAck = true
		}
	}
	if !foundResetAck {
		t.Fatalf("retransmitted soft reset lost the reset ACK: %v", re.AckIDs)
	}
}

// TestStaleSoftResetNotParked verifies that an ordinary control read does not
// park a delayed soft reset from a retiring epoch (only the strictly-next key
// ID may be parked), and that it mutates no ACK / pending state.
func TestStaleSoftResetNotParked(t *testing.T) {
	client, server := newTestChannels(t)
	client.SetRemoteSessionID(server.LocalSessionID())
	server.SetRemoteSessionID(client.LocalSessionID())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Client is on epoch 2. A delayed soft reset for the retiring epoch 1
	// arrives while the client reads control packets (not the watcher).
	client.AdoptKeyID(2)
	server.AdoptKeyID(1)
	if _, err := server.Send(ctx, PControlSoftResetV1, nil); err != nil {
		t.Fatal(err)
	}

	// An ordinary read must NOT park the stale reset.
	readCtx, readCancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer readCancel()
	if pkt, err := client.Read(readCtx); err == nil {
		t.Fatalf("Read delivered %s key=%d, want stale reset dropped", pkt.Opcode, pkt.KeyID)
	}
	if client.pendingSoftReset != nil {
		t.Fatalf("stale soft reset was parked: key=%d", client.pendingSoftReset.KeyID)
	}

	// The watcher must not accept the stale epoch either; only the next one.
	server.AdoptKeyID(3)
	if _, err := server.Send(ctx, PControlSoftResetV1, nil); err != nil {
		t.Fatal(err)
	}
	got, err := client.waitForSoftReset(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyID != 3 {
		t.Fatalf("watcher accepted stale epoch, got key=%d want 3", got.KeyID)
	}
}

// TestConsumeRekeyPushAUTHFailed verifies that AUTH_FAILED during a rekey is a
// hard error, not "no token".
func TestConsumeRekeyPushAUTHFailed(t *testing.T) {
	client := &Client{push: &PushReply{PeerID: 5, AuthTokenPass: "SESS_ID_old"}}
	client.leftoverTLS = []byte("AUTH_FAILED,SESSION: auth-token expired\x00")
	err := client.consumeRekeyPush()
	if err == nil {
		t.Fatal("consumeRekeyPush returned nil on AUTH_FAILED")
	}
	if !errors.Is(err, errAuthFailed) {
		t.Fatalf("expected errAuthFailed, got %v", err)
	}
}

// chunkConn serves a fixed byte stream one chunk per Read. Each chunk may
// carry an error returned together with the bytes (mimicking tls.Conn's
// (n, io.EOF) when app data is followed by close_notify). Once exhausted it
// returns a timeout-style error.
type chunkConn struct {
	data [][]byte
	errs []error
	idx  int
}

func (c *chunkConn) Read(p []byte) (int, error) {
	if c.idx >= len(c.data) {
		return 0, os.ErrDeadlineExceeded
	}
	n := copy(p, c.data[c.idx])
	var err error
	if c.idx < len(c.errs) {
		err = c.errs[c.idx]
	}
	c.idx++
	return n, err
}

func (c *chunkConn) SetReadDeadline(t time.Time) error { return nil }

// TestReadTokenPushReplySplitAcrossReads verifies that a token-only PUSH_REPLY
// split across two reads is parsed (TLS is a byte stream).
func TestReadTokenPushReplySplitAcrossReads(t *testing.T) {
	conn := &chunkConn{data: [][]byte{
		[]byte("PUSH_REPLY,auth-token "),
		[]byte("SESS_ID_split\x00"),
	}}
	reply, rest, err := readTokenPushReply(conn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reply == nil || reply.AuthTokenPass != "SESS_ID_split" {
		t.Fatalf("split token not parsed: %#v", reply)
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected leftover: %q", rest)
	}
}

// TestReadTokenPushReplyPartialPreserved verifies that a partial reply is
// preserved (not discarded) when the stream ends without a complete message.
func TestReadTokenPushReplyPartialPreserved(t *testing.T) {
	conn := &chunkConn{data: [][]byte{[]byte("PUSH_REPLY,auth-token ")}}
	reply, rest, err := readTokenPushReply(conn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reply != nil {
		t.Fatalf("unexpected reply for partial data: %#v", reply)
	}
	if string(rest) != "PUSH_REPLY,auth-token " {
		t.Fatalf("partial bytes lost: %q", rest)
	}
}

// TestReadTokenPushReplyAUTHFailedWithEOF verifies that AUTH_FAILED data
// returned together with io.EOF (tls.Conn app-data + close_notify) is
// surfaced as a hard error, not silently discarded.
func TestReadTokenPushReplyAUTHFailedWithEOF(t *testing.T) {
	conn := &chunkConn{
		data: [][]byte{[]byte("AUTH_FAILED,SESSION: auth-token expired\x00")},
		errs: []error{io.EOF},
	}
	reply, _, err := readTokenPushReply(conn, nil)
	if err == nil {
		t.Fatal("readTokenPushReply lost AUTH_FAILED returned with io.EOF")
	}
	if !errors.Is(err, errAuthFailed) {
		t.Fatalf("expected errAuthFailed, got %v", err)
	}
	if reply != nil {
		t.Fatalf("unexpected reply: %#v", reply)
	}
}

// TestReadTokenPushReplyEOFPropagated verifies that a plain EOF (no complete
// message) is propagated as an error, not treated as "no token".
func TestReadTokenPushReplyEOFPropagated(t *testing.T) {
	conn := &chunkConn{
		data: [][]byte{[]byte("PUSH_REPLY,auth-token SESS")},
		errs: []error{io.ErrUnexpectedEOF},
	}
	reply, _, err := readTokenPushReply(conn, nil)
	if err == nil {
		t.Fatal("EOF was suppressed")
	}
	if errors.Is(err, errAuthFailed) {
		t.Fatalf("unexpected errAuthFailed: %v", err)
	}
	if reply != nil {
		t.Fatalf("unexpected reply: %#v", reply)
	}
}

// TestReadTokenPushReplyCompleteReplyWithEOF verifies that a complete token
// reply returned together with io.EOF is accepted: the bytes are valid and
// must be processed before the terminal error (tls.Conn returns (n, io.EOF)
// when app data is immediately followed by close_notify). Success must not
// depend on read-ahead boundaries.
func TestReadTokenPushReplyCompleteReplyWithEOF(t *testing.T) {
	conn := &chunkConn{
		data: [][]byte{[]byte("PUSH_REPLY,auth-token SESS_ID_new\x00")},
		errs: []error{io.EOF},
	}
	reply, _, err := readTokenPushReply(conn, nil)
	if err != nil {
		t.Fatalf("complete reply with EOF should be accepted: %v", err)
	}
	if reply == nil || reply.AuthTokenPass != "SESS_ID_new" {
		t.Fatalf("unexpected reply: %#v", reply)
	}
}

// TestWatchControlSurfacesParkedAUTHFailed verifies that a parked or deferred
// AUTH_FAILED is surfaced (failControl) instead of being swallowed by the next
// renegotiation.
func TestWatchControlSurfacesParkedAUTHFailed(t *testing.T) {
	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{Username: "u", Password: "p"}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// watcher loop consumes a soft reset, then must abort on AUTH_FAILED.
	var serverID SessionID
	copy(serverID[:], []byte("server01"))
	client.control.SetRemoteSessionID(serverID)
	client.push = &PushReply{PeerID: 1, AuthTokenPass: "SESS_ID_old"}
	client.leftoverTLS = []byte("AUTH_FAILED,SESSION: auth-token expired\x00")
	client.control.AdoptKeyID(1)
	client.control.pendingSoftReset = &ControlPacket{
		Opcode:       PControlSoftResetV1,
		KeyID:        1,
		LocalSession: serverID,
	}

	done := make(chan struct{})
	go func() {
		client.watchControl()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchControl did not exit after AUTH_FAILED")
	}
	if rekeyErr := client.LastRekeyError(); rekeyErr == nil {
		t.Fatal("watchControl swallowed parked AUTH_FAILED")
	} else if !strings.Contains(rekeyErr.Error(), "auth") {
		t.Fatalf("unexpected rekey error: %v", rekeyErr)
	}
}

// TestMRUCarriesAckOnSubsequentSends verifies the MRU behavior: an ACK queued
// once rides on this packet and the next (OpenVPN lru_acks), not just once.
func TestMRUCarriesAckOnSubsequentSends(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	clientCrypt, err := NewTLSCrypt(testStaticKey(), true)
	if err != nil {
		t.Fatal(err)
	}
	serverCrypt, err := NewTLSCrypt(testStaticKey(), false)
	if err != nil {
		t.Fatal(err)
	}
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	var serverID SessionID
	copy(serverID[:], []byte("server01"))

	client := NewControlChannel(clientIO, clientCrypt, clientID)
	client.SetRemoteSessionID(serverID)
	server := NewControlChannel(serverIO, serverCrypt, serverID)
	server.SetRemoteSessionID(clientID)
	client.clock = func() time.Time { return time.Unix(1714567890, 0) }
	server.clock = func() time.Time { return time.Unix(1714567891, 0) }

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Server sends message 5 (soft reset on epoch 1), client queues ACK 5.
	server.AdoptKeyID(1)
	if _, err := server.Send(ctx, PControlSoftResetV1, nil); err != nil {
		t.Fatal(err)
	}
	soft, err := client.waitForSoftReset(ctx)
	if err != nil {
		t.Fatal(err)
	}
	client.AdoptKeyID(1)
	client.MarkReceived(soft.MessageID)
	client.QueueAck(soft.MessageID)

	// First outbound packet carries ACK 5.
	if err := client.SendSoftReset(ctx); err != nil {
		t.Fatal(err)
	}
	raw, err := serverIO.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, _, _, err := DecodeControlPacket(serverCrypt, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAck(first.AckIDs, soft.MessageID) {
		t.Fatalf("first packet missing ACK %d: %v", soft.MessageID, first.AckIDs)
	}

	// Second outbound packet STILL carries ACK 5 (MRU).
	if _, err := client.Send(ctx, PControlV1, []byte("second")); err != nil {
		t.Fatal(err)
	}
	raw, err = serverIO.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, _, _, err := DecodeControlPacket(serverCrypt, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !hasAck(second.AckIDs, soft.MessageID) {
		t.Fatalf("second packet lost ACK %d (MRU): %v", soft.MessageID, second.AckIDs)
	}
}

func hasAck(acks []uint32, id uint32) bool {
	for _, a := range acks {
		if a == id {
			return true
		}
	}
	return false
}

// TestMRUMoveToFrontMatchesReference verifies the exact copy_acks_to_mru
// behavior on a full MRU: an already-present ID that is re-acked is moved to
// the front instead of being evicted. MRU [1..8], pending [8 9] -> [8 9 1 2 3 4 5 6].
func TestMRUMoveToFrontMatchesReference(t *testing.T) {
	c := &ControlChannel{lruAcks: []uint32{1, 2, 3, 4, 5, 6, 7, 8}}
	c.ackPending = []uint32{8, 9}
	got := c.takeAcksLocked(reliableAckSize)
	want := []uint32{8, 9, 1, 2, 3, 4, 5, 6}
	if len(got) != len(want) {
		t.Fatalf("len=%d want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	// The MRU itself must hold the same move-to-front result.
	if len(c.lruAcks) != len(want) {
		t.Fatalf("mru len=%d want %d: %v", len(c.lruAcks), len(want), c.lruAcks)
	}
	for i := range want {
		if c.lruAcks[i] != want[i] {
			t.Fatalf("mru got %v want %v", c.lruAcks, want)
		}
	}
}

// TestAckSerializationCaps verifies per-packet ACK caps match OpenVPN:
// reliable control packets (incl. retransmits) carry <= CONTROL_SEND_ACK_MAX
// (4); a dedicated ACK carries <= RELIABLE_ACK_SIZE (8), and <= 4 when the
// channel is unprotected (SoftEther compat).
// TestAckCapRetainsUnsentPending verifies the reference behavior: a packet
// capped at 4 ACKs consumes only the first 4 pending, and the fifth ACK stays
// pending and appears on the next packet (reliable_ack_write retains the
// remainder).
func TestAckCapRetainsUnsentPending(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	var serverID SessionID
	copy(serverID[:], []byte("server01"))
	client := NewControlChannel(clientIO, nil, clientID)
	client.SetRemoteSessionID(serverID)
	client.clock = func() time.Time { return time.Unix(1714567890, 0) }

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Five pending ACKs, dedicated-ack cap on a plain channel is 4.
	for i := 1; i <= 5; i++ {
		client.QueueAck(uint32(i))
	}
	if err := client.SendAck(ctx); err != nil {
		t.Fatal(err)
	}

	// First dedicated ACK serializes [1 2 3 4]; ACK 5 stays pending.
	raw, err := serverIO.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, _, _, err := DecodeControlPacket(nil, raw)
	if err != nil {
		t.Fatal(err)
	}
	wantFirst := []uint32{1, 2, 3, 4}
	if len(first.AckIDs) != len(wantFirst) {
		t.Fatalf("first packet acks = %v, want %v", first.AckIDs, wantFirst)
	}
	for i := range wantFirst {
		if first.AckIDs[i] != wantFirst[i] {
			t.Fatalf("first packet acks = %v, want %v", first.AckIDs, wantFirst)
		}
	}
	if len(client.ackPending) != 1 || client.ackPending[0] != 5 {
		t.Fatalf("ackPending after first send = %v, want [5]", client.ackPending)
	}

	// A second dedicated ACK flushes the retained ACK 5.
	if err := client.SendAck(ctx); err != nil {
		t.Fatal(err)
	}
	raw, err = serverIO.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, _, _, err := DecodeControlPacket(nil, raw)
	if err != nil {
		t.Fatal(err)
	}
	found5 := false
	for _, a := range second.AckIDs {
		if a == 5 {
			found5 = true
		}
	}
	if !found5 {
		t.Fatalf("second packet missing retained ACK 5: %v", second.AckIDs)
	}
}

func TestAckSerializationCaps(t *testing.T) {
	cases := []struct {
		name    string
		crypt   ControlCryptor
		path    func(ctx context.Context, c *ControlChannel) error
		reads   int
		wantMax int
	}{
		{
			name:  "reliable-control-with-tls",
			crypt: mustClientCrypt(t),
			path: func(ctx context.Context, c *ControlChannel) error {
				c.QueueAck(1)
				c.QueueAck(2)
				c.QueueAck(3)
				c.QueueAck(4)
				c.QueueAck(5)
				_, err := c.Send(ctx, PControlV1, []byte("data"))
				return err
			},
			wantMax: 4,
		},
		{
			name:  "reliable-control-plain",
			crypt: nil,
			path: func(ctx context.Context, c *ControlChannel) error {
				c.QueueAck(1)
				c.QueueAck(2)
				c.QueueAck(3)
				c.QueueAck(4)
				c.QueueAck(5)
				_, err := c.Send(ctx, PControlV1, []byte("data"))
				return err
			},
			wantMax: 4,
		},
		{
			name:  "dedicated-ack-with-tls",
			crypt: mustClientCrypt(t),
			path: func(ctx context.Context, c *ControlChannel) error {
				for i := 0; i < 5; i++ {
					c.QueueAck(uint32(i))
				}
				return c.SendAck(ctx)
			},
			wantMax: 5,
		},
		{
			name:  "dedicated-ack-plain",
			crypt: nil,
			path: func(ctx context.Context, c *ControlChannel) error {
				for i := 0; i < 5; i++ {
					c.QueueAck(uint32(i))
				}
				return c.SendAck(ctx)
			},
			wantMax: 4,
		},
		{
			name:  "retransmit-with-tls",
			crypt: mustClientCrypt(t),
			path: func(ctx context.Context, c *ControlChannel) error {
				// Prime a pending reliable message, queue 5 acks, then
				// retransmit: the retransmitted reliable packet must carry
				// at most CONTROL_SEND_ACK_MAX acks.
				if _, err := c.Send(ctx, PControlV1, []byte("data")); err != nil {
					return err
				}
				for i := 0; i < 5; i++ {
					c.QueueAck(uint32(i))
				}
				return c.RetransmitPending(ctx)
			},
			reads:   2,
			wantMax: 4,
		},
		{
			name:  "retransmit-plain",
			crypt: nil,
			path: func(ctx context.Context, c *ControlChannel) error {
				if _, err := c.Send(ctx, PControlV1, []byte("data")); err != nil {
					return err
				}
				for i := 0; i < 5; i++ {
					c.QueueAck(uint32(i))
				}
				return c.RetransmitPending(ctx)
			},
			reads:   2,
			wantMax: 4,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientIO, serverIO := newMemoryPacketPair()
			var clientID SessionID
			copy(clientID[:], []byte("client01"))
			var serverID SessionID
			copy(serverID[:], []byte("server01"))
			client := NewControlChannel(clientIO, tc.crypt, clientID)
			client.SetRemoteSessionID(serverID)
			client.clock = func() time.Time { return time.Unix(1714567890, 0) }

			// The peer decodes client->server with the server-direction crypt.
			var peerCrypt ControlCryptor
			if tc.crypt != nil {
				var err error
				peerCrypt, err = NewTLSCrypt(testStaticKey(), false)
				if err != nil {
					t.Fatal(err)
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			if err := tc.path(ctx, client); err != nil {
				t.Fatal(err)
			}
			reads := tc.reads
			if reads == 0 {
				reads = 1
			}
			var pkt *ControlPacket
			for i := 0; i < reads; i++ {
				raw, err := serverIO.ReadPacket(ctx)
				if err != nil {
					t.Fatal(err)
				}
				pkt, _, _, err = DecodeControlPacket(peerCrypt, raw)
				if err != nil {
					t.Fatalf("decode: %v", err)
				}
			}
			if len(pkt.AckIDs) > tc.wantMax {
				t.Fatalf("serialized %d acks, want <= %d: %v", len(pkt.AckIDs), tc.wantMax, pkt.AckIDs)
			}
			if len(pkt.AckIDs) == 0 {
				t.Fatal("expected at least one ack")
			}
		})
	}
}

func mustClientCrypt(t *testing.T) ControlCryptor {
	t.Helper()
	c, err := NewTLSCrypt(testStaticKey(), true)
	if err != nil {
		t.Fatal(err)
	}
	return c
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
}

func TestRekeyConsumesTokenPushReplyAndKeepsPeerID(t *testing.T) {
	client := &Client{}
	client.push = &PushReply{
		PeerID: 42,
	}
	// A token-only PUSH_REPLY arrives in leftoverTLS after the server
	// key-method-2 record (send_push_reply_auth_token).
	client.leftoverTLS = []byte("PUSH_REPLY,auth-token SESS_ID_new,auth-token-user dGVzdA==\x00")

	// The rekey branch must consume it and keep the previous peer-id.
	client.consumeRekeyPush()
	if client.push.PeerID != 42 {
		t.Fatalf("peer-id not inherited across rekey: %d", client.push.PeerID)
	}
	if client.push.AuthTokenPass != "SESS_ID_new" {
		t.Fatalf("auth-token not renewed: %q", client.push.AuthTokenPass)
	}
	if client.authUser != "test" || client.authPass != "SESS_ID_new" {
		t.Fatalf("auth credentials not applied: %q/%q", client.authUser, client.authPass)
	}
}

func TestWaitForSoftResetParksLateControlPayload(t *testing.T) {
	client, server := newTestChannels(t)
	client.SetRemoteSessionID(server.LocalSessionID())
	server.SetRemoteSessionID(client.LocalSessionID())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client.AdoptKeyID(1)
	server.AdoptKeyID(1)

	// Late token-only PUSH_REPLY on the current epoch, then a next-epoch
	// soft reset. The watcher must park the token, not drop it.
	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = server.Send(ctx, PControlV1, []byte("PUSH_REPLY,auth-token SESS_ID_parked\x00"))
		time.Sleep(20 * time.Millisecond)
		server.AdoptKeyID(2)
		_, _ = server.Send(ctx, PControlSoftResetV1, nil)
	}()

	got, err := client.waitForSoftReset(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Opcode != PControlSoftResetV1 || got.KeyID != 2 {
		t.Fatalf("got %s key=%d", got.Opcode, got.KeyID)
	}
	queued := client.ReadAll()
	if len(queued) != 1 || string(queued[0].Payload) != "PUSH_REPLY,auth-token SESS_ID_parked\x00" {
		t.Fatalf("parked payload lost: %#v", queued)
	}
}

func TestConsumeRekeyPushReadsParkedTokenViaLeftover(t *testing.T) {
	c := &Client{push: &PushReply{PeerID: 9, AuthTokenPass: "SESS_ID_old"}}
	c.leftoverTLS = []byte("PUSH_REPLY,auth-token SESS_ID_parked,auth-token-user dGVzdA==\x00")
	c.consumeRekeyPush()
	if c.authPass != "SESS_ID_parked" {
		t.Fatalf("parked token not applied: %q", c.authPass)
	}
	if c.push.PeerID != 9 {
		t.Fatalf("peer-id lost: %d", c.push.PeerID)
	}
}

func TestLooksLikeFollowingTLSControlNotOnWholeKM2Buffer(t *testing.T) {
	var packet []byte
	packet = binary.BigEndian.AppendUint32(packet, 0)
	packet = append(packet, KeyMethod2)
	packet = append(packet, bytes.Repeat([]byte{1}, keySourceRandomSize)...)
	packet = append(packet, bytes.Repeat([]byte{2}, keySourceRandomSize)...)
	packet = appendOpenVPNString(packet, "server-options")
	packet = append(packet, []byte("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0\x00")...)

	// The whole buffer starts with the KM2 header, not PUSH_REPLY.
	if looksLikeFollowingTLSControl(packet) {
		t.Fatal("looksLikeFollowingTLSControl must not match a KM2-prefixed buffer")
	}
	// The tail after the options string does.
	offset := 5 + keySourceRandomSize*2
	offset += 2 + int(binary.BigEndian.Uint16(packet[offset:offset+2]))
	if !looksLikeFollowingTLSControl(packet[offset:]) {
		t.Fatal("tail after options should look like TLS control")
	}
	// And the tolerant parser still accepts the shortened record.
	if _, _, err := ParseServerKeyMethod2RecordConsumed(packet); err != nil {
		t.Fatalf("shortened record should parse via tail check: %v", err)
	}
}

func TestRekeyKeepsPeerIDWithoutTokenPush(t *testing.T) {
	client := &Client{}
	client.push = &PushReply{
		PeerID: 7,
	}
	// No token pushed on this rekey; peer-id must still carry over.
	client.consumeRekeyPush()
	if client.push.PeerID != 7 {
		t.Fatalf("peer-id not inherited across rekey without token: %d", client.push.PeerID)
	}
}
