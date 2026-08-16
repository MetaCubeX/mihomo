package openvpn

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/tls"
)

func newTestTLSServerCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mihomo-openvpn-test"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, certPEM
}

func marshalTestServerKeyMethod(t *testing.T) []byte {
	t.Helper()
	var random1, random2 [keySourceRandomSize]byte
	if _, err := rand.Read(random1[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(random2[:]); err != nil {
		t.Fatal(err)
	}
	out := binary.BigEndian.AppendUint32(nil, 0)
	out = append(out, KeyMethod2)
	out = append(out, random1[:]...)
	out = append(out, random2[:]...)
	out = appendOpenVPNString(out, InstallScriptOptionsString(ProtoUDP, CipherAES128GCM, AuthSHA256, ""))
	out = appendOpenVPNString(out, "")
	out = appendOpenVPNString(out, "")
	out = appendOpenVPNString(out, "")
	return out
}

func clientKeyMethodComplete(packet []byte) bool {
	const fixed = 4 + 1 + keySourcePreMasterSize + keySourceRandomSize*2
	if len(packet) < fixed {
		return false
	}
	offset := fixed
	for i := 0; i < 4; i++ {
		if !km2StrComplete(packet, offset) {
			return false
		}
		offset += 2 + int(binary.BigEndian.Uint16(packet[offset:offset+2]))
	}
	return true
}

func readTestClientKeyMethod(conn net.Conn) error {
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 1024)
	for !clientKeyMethodComplete(buf) {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func TestRealTLSRekeySurvivesExtendedAuthPending(t *testing.T) {
	for _, useTLSAuth := range []bool{false, true} {
		name := "plain"
		if useTLSAuth {
			name = "tls-auth"
		}
		t.Run(name, func(t *testing.T) {
			clientIO, serverIO := newMemoryPacketPair()
			certificate, caPEM := newTestTLSServerCertificate(t)
			serverKM2 := marshalTestServerKeyMethod(t)
			config := &ClientConfig{
				Proto:               ProtoUDP,
				Cipher:              CipherAES128GCM,
				Auth:                AuthSHA256,
				CA:                  caPEM,
				Username:            "test",
				TransitionWindow:    time.Minute,
				TransitionWindowSet: true,
			}
			var serverCrypt ControlCryptor
			if useTLSAuth {
				staticKey := bytes.Repeat([]byte{0x42}, staticKeySize)
				config.TLSAuthKey = staticKey
				config.KeyDirection = "1"
				var err error
				serverCrypt, err = NewTLSAuth(staticKey, "0")
				if err != nil {
					t.Fatal(err)
				}
			}
			client, err := NewClient(config, clientIO)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.rekeyHandshakeTimeout = 250 * time.Millisecond

			var serverID SessionID
			copy(serverID[:], []byte("server01"))
			client.control.SetRemoteSessionID(serverID)
			server := NewControlChannel(serverIO, serverCrypt, serverID)
			server.SetRemoteSessionID(client.control.LocalSessionID())

			keys := &KeyMaterial{
				SendCipherKey: bytes.Repeat([]byte{0x11}, 16),
				SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
				RecvCipherKey: bytes.Repeat([]byte{0x33}, 16),
				RecvHMACKey:   bytes.Repeat([]byte{0x44}, maxHMACKeyLength),
			}
			oldData, err := NewDataChannel(keys, CipherAES128GCM, AuthSHA256, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			client.installDataChannel(oldData)
			client.push = &PushReply{
				Prefixes:     []netip.Prefix{netip.MustParsePrefix("10.8.0.2/24")},
				PeerID:       0,
				Cipher:       CipherAES128GCM,
				HasPushReply: true,
			}
			client.negotiatedCipher = CipherAES128GCM
			client.controlConn = NewControlConn(client.control)
			// A rekey starts with an established previous epoch. Production must
			// clear this value, then capture a fresh anchor only after server KM2.
			client.controlEstablishedAt = time.Now().Add(-time.Hour)

			server.AdoptKeyID(1)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := server.Send(ctx, PControlSoftResetV1, nil); err != nil {
				t.Fatal(err)
			}
			reset, err := client.control.waitForSoftReset(ctx)
			if err != nil {
				t.Fatal(err)
			}
			retiringExpiry := client.retiringWindowDeadline(reset)
			client.stageRetiringWindow(retiringExpiry)

			serverErr := make(chan error, 1)
			clientKM2Read := make(chan time.Time, 1)
			releaseServerKM2 := make(chan struct{})
			go func() {
				// ControlChannel is a client-side production type. The test peer
				// consumes the client's reset here, then hands the same reliable
				// stream to tls.Server for the actual TLS/KM2/PUSH exchange.
				rawReset, err := serverIO.ReadPacket(ctx)
				if err != nil {
					serverErr <- fmt.Errorf("read client soft reset: %w", err)
					return
				}
				clientReset, _, _, err := DecodeControlPacket(serverCrypt, rawReset)
				if err != nil {
					serverErr <- fmt.Errorf("decode client soft reset: %w", err)
					return
				}
				if clientReset.Opcode != PControlSoftResetV1 || clientReset.KeyID != 1 || clientReset.MessageID != 0 {
					serverErr <- fmt.Errorf("unexpected client reset: opcode=%s key=%d message=%d", clientReset.Opcode, clientReset.KeyID, clientReset.MessageID)
					return
				}
				server.mu.Lock()
				for _, ackID := range clientReset.AckIDs {
					delete(server.pending, ackID)
				}
				server.recvMessage = 1
				server.ackPending = appendAck(server.ackPending, clientReset.MessageID)
				server.mu.Unlock()
				serverConn := NewControlConn(server)
				serverTLS := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{certificate}})
				if err := serverTLS.HandshakeContext(ctx); err != nil {
					serverErr <- fmt.Errorf("server TLS handshake: %w", err)
					return
				}
				if err := readTestClientKeyMethod(serverTLS); err != nil {
					serverErr <- fmt.Errorf("read client KM2: %w", err)
					return
				}
				clientKM2Read <- time.Now()
				select {
				case <-releaseServerKM2:
				case <-ctx.Done():
					serverErr <- ctx.Err()
					return
				}
				if _, err := serverTLS.Write(serverKM2); err != nil {
					serverErr <- fmt.Errorf("write server KM2: %w", err)
					return
				}
				if _, err := serverTLS.Write([]byte("AUTH_PENDING,timeout 2\x00PUSH_REPLY,push-continuation 2\x00")); err != nil {
					serverErr <- fmt.Errorf("write deferred push: %w", err)
					return
				}
				time.Sleep(500 * time.Millisecond)
				if _, err := serverTLS.Write([]byte("PUSH_REPLY,auth-token SESS_ID_rotated,push-continuation 1\x00")); err != nil {
					serverErr <- fmt.Errorf("write final push: %w", err)
					return
				}
				serverErr <- nil
			}()

			started := time.Now()
			rekeyErr := make(chan error, 1)
			go func() {
				rekeyErr <- client.renegotiate(reset, retiringExpiry)
			}()
			var clientKM2ReadAt time.Time
			select {
			case clientKM2ReadAt = <-clientKM2Read:
			case err := <-rekeyErr:
				t.Fatalf("client rekey ended before sending KM2: %v", err)
			case err := <-serverErr:
				t.Fatalf("server ended before reading client KM2: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if !client.controlEstablishedAt.IsZero() {
				t.Fatalf("AUTH_PENDING anchor captured before server KM2: %v", client.controlEstablishedAt)
			}
			serverKM2ReleasedAt := time.Now()
			close(releaseServerKM2)
			select {
			case err := <-rekeyErr:
				if err != nil {
					select {
					case serverFailure := <-serverErr:
						t.Fatalf("client rekey: %v; server: %v", err, serverFailure)
					default:
						t.Fatal(err)
					}
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if elapsed := time.Since(started); elapsed < client.rekeyTimeout() {
				t.Fatalf("rekey completed before deferred auth delay: %v", elapsed)
			}
			if err := <-serverErr; err != nil {
				t.Fatal(err)
			}
			establishedAt := client.controlEstablishedAt
			if establishedAt.Before(serverKM2ReleasedAt) || establishedAt.Before(clientKM2ReadAt) {
				t.Fatalf("AUTH_PENDING anchor %v predates KM2 activation (read %v, released %v)", establishedAt, clientKM2ReadAt, serverKM2ReleasedAt)
			}
			client.dataLock.RLock()
			activeKeyID := client.data.keyID
			deferredUntil := client.deferredUntil
			client.dataLock.RUnlock()
			if activeKeyID != 1 {
				t.Fatalf("active data key ID = %d, want 1", activeKeyID)
			}
			if want := establishedAt.Add(2 * time.Second); !deferredUntil.Equal(want) {
				t.Fatalf("AUTH_PENDING deadline = %v, want KM2 anchor deadline %v", deferredUntil, want)
			}
			if client.authPass != "SESS_ID_rotated" {
				t.Fatalf("rotated auth token = %q", client.authPass)
			}
		})
	}
}

func TestClientPropagatesDataPacketIDExhaustion(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	keys := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x11}, 16),
		SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x33}, 16),
		RecvHMACKey:   bytes.Repeat([]byte{0x44}, maxHMACKeyLength),
	}
	data, err := NewDataChannel(keys, CipherAES128GCM, AuthSHA256, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	data.sendPacketID = dataPacketIDRekeyThreshold
	client.installDataChannel(data)
	err = client.WriteIPPacket(context.Background(), []byte{0x45, 0, 0, 20})
	if !errors.Is(err, errDataPacketIDExhausted) {
		t.Fatalf("exhausted packet returned %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := serverIO.ReadPacket(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("exhausted packet reached transport: %v", err)
	}
}

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

	err = client.renegotiate(nil, time.Time{})
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

	// A new-epoch reset is always message 0; any other message ID would
	// corrupt the receive sequence and must be rejected.
	pktBadMsg := &ControlPacket{Opcode: PControlSoftResetV1, KeyID: 2, MessageID: 5, LocalSession: serverID}
	softReset, valid = client.classifyWatchPacketLocked(pktBadMsg)
	if softReset || valid {
		t.Fatalf("expected soft reset with message id 5 to be rejected")
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

// TestOutboundKeyStaysLameDuckUntilPeerEvidence verifies the deferred-auth
// outbound key selection: after a rekey installs a new data epoch, outbound
// packets keep using the old (lame-duck) key until a packet labeled with the
// new key ID decrypts successfully — the OpenVPN-equivalent signal that the
// peer has activated the new key.
// TestRekeyKeepsOldOutboundEvenIfNeverSent reproduces the review point 2: a
// rekey on a quiet / receive-only tunnel (the old epoch never sent a packet)
// must still keep the old key for outbound, because only the very first
// handshake (old == nil) starts on the new key. The old key's send counter
// is irrelevant.
func TestRekeyKeepsOldOutboundEvenIfNeverSent(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{Username: "u", Password: "p"}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	mk := func() *KeyMaterial {
		k := &KeyMaterial{
			SendCipherKey: make([]byte, 16),
			SendHMACKey:   make([]byte, maxHMACKeyLength),
			RecvCipherKey: make([]byte, 16),
			RecvHMACKey:   make([]byte, maxHMACKeyLength),
		}
		for i := range k.SendCipherKey {
			k.SendCipherKey[i] = 0x11
		}
		copy(k.RecvCipherKey, k.SendCipherKey)
		for i := range k.SendHMACKey {
			k.SendHMACKey[i] = 0x22
		}
		copy(k.RecvHMACKey, k.SendHMACKey)
		return k
	}
	initial, err := NewDataChannel(mk(), CipherAES128GCM, AuthSHA256, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	rekeyed, err := NewDataChannel(mk(), CipherAES128GCM, AuthSHA256, 7, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Install initial, but NEVER send on it: the tunnel is quiet.
	client.installDataChannel(initial)
	client.installDataChannel(rekeyed)

	// Outbound must still be the old key (id 0) — not the new key.
	if err := client.writeDataPacket(context.Background(), []byte{0x45, 0, 0, 20}, false); err != nil {
		t.Fatal(err)
	}
	pkt, err := serverIO.ReadPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, keyID := parseOpcodeKeyID(pkt[0]); keyID != 0 {
		t.Fatalf("outbound key ID after quiet rekey = %d; want 0 (old key kept)", keyID)
	}
}

// TestFailedDecryptDoesNotPromote reproduces the review point 1: a packet
// that fails decryption (malformed / forged) must not set peer evidence and
// must not promote the new outbound key.
func TestFailedDecryptDoesNotPromote(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{Username: "u", Password: "p"}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	mk := func() *KeyMaterial {
		k := &KeyMaterial{
			SendCipherKey: make([]byte, 16),
			SendHMACKey:   make([]byte, maxHMACKeyLength),
			RecvCipherKey: make([]byte, 16),
			RecvHMACKey:   make([]byte, maxHMACKeyLength),
		}
		for i := range k.SendCipherKey {
			k.SendCipherKey[i] = 0x11
		}
		copy(k.RecvCipherKey, k.SendCipherKey)
		for i := range k.SendHMACKey {
			k.SendHMACKey[i] = 0x22
		}
		copy(k.RecvHMACKey, k.SendHMACKey)
		return k
	}
	initial, err := NewDataChannel(mk(), CipherAES128GCM, AuthSHA256, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	rekeyed, err := NewDataChannel(mk(), CipherAES128GCM, AuthSHA256, 7, 1)
	if err != nil {
		t.Fatal(err)
	}
	client.installDataChannel(initial)
	client.installDataChannel(rekeyed)

	// A malformed packet labeled with the new key id must fail decryption and
	// must NOT latch evidence (the review's in-memory regression: a one-byte
	// P_DATA_V2 with the new key id).
	bad := []byte{opcodeKeyID(PDataV2, 1)}
	if _, err := client.decryptDataPacket(bad); err == nil {
		t.Fatal("malformed new-key packet unexpectedly decrypted")
	}
	if rekeyed.PeerActive() {
		t.Fatal("failed decryption latched peer evidence")
	}

	// Outbound stays on the old key after the failed decrypt.
	if err := client.writeDataPacket(context.Background(), []byte{0x45, 0, 0, 20}, false); err != nil {
		t.Fatal(err)
	}
	pkt, err := serverIO.ReadPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, keyID := parseOpcodeKeyID(pkt[0]); keyID != 0 {
		t.Fatalf("outbound key ID after failed decrypt = %d; want 0", keyID)
	}
}

// TestOutboundPromotesAfterAuthDeferredExpire verifies the no-evidence
// backstop mirrors OpenVPN's auth_deferred_expire window (~60s), not the old
// key's destruction time: after the window elapses with no peer evidence, a
// one-way tunnel still rotates outbound to the new key.
func TestOutboundPromotesAfterAuthDeferredExpire(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{Username: "u", Password: "p"}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	mk := func() *KeyMaterial {
		k := &KeyMaterial{
			SendCipherKey: make([]byte, 16),
			SendHMACKey:   make([]byte, maxHMACKeyLength),
			RecvCipherKey: make([]byte, 16),
			RecvHMACKey:   make([]byte, maxHMACKeyLength),
		}
		for i := range k.SendCipherKey {
			k.SendCipherKey[i] = 0x11
		}
		copy(k.RecvCipherKey, k.SendCipherKey)
		for i := range k.SendHMACKey {
			k.SendHMACKey[i] = 0x22
		}
		copy(k.RecvHMACKey, k.SendHMACKey)
		return k
	}
	initial, err := NewDataChannel(mk(), CipherAES128GCM, AuthSHA256, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	rekeyed, err := NewDataChannel(mk(), CipherAES128GCM, AuthSHA256, 7, 1)
	if err != nil {
		t.Fatal(err)
	}
	client.installDataChannel(initial)
	client.installDataChannel(rekeyed)

	// Before the window elapses, outbound stays on the old key (no evidence).
	if err := client.writeDataPacket(context.Background(), []byte{0x45, 0, 0, 20}, false); err != nil {
		t.Fatal(err)
	}
	pkt, _ := serverIO.ReadPacket(context.Background())
	if _, keyID := parseOpcodeKeyID(pkt[0]); keyID != 0 {
		t.Fatalf("outbound before window = %d; want 0", keyID)
	}

	// Simulate the auth_deferred_expire window elapsing.
	client.outboundStart = time.Now().Add(-authDeferredExpire - time.Second)

	if err := client.writeDataPacket(context.Background(), []byte{0x45, 0, 0, 20}, false); err != nil {
		t.Fatal(err)
	}
	pkt, _ = serverIO.ReadPacket(context.Background())
	if _, keyID := parseOpcodeKeyID(pkt[0]); keyID != 1 {
		t.Fatalf("outbound after window = %d; want 1", keyID)
	}
}

// TestAuthPendingTimeoutDoesNotExtendOutboundSelection verifies AUTH_PENDING
// remains control/deferred-auth metadata and cannot replace the independent
// outbound auth_deferred_expire selection window.
func TestAuthPendingTimeoutDoesNotExtendOutboundSelection(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{Username: "u", Password: "p"}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	mk := func() *KeyMaterial {
		k := &KeyMaterial{
			SendCipherKey: make([]byte, 16),
			SendHMACKey:   make([]byte, maxHMACKeyLength),
			RecvCipherKey: make([]byte, 16),
			RecvHMACKey:   make([]byte, maxHMACKeyLength),
		}
		for i := range k.SendCipherKey {
			k.SendCipherKey[i] = 0x11
		}
		copy(k.RecvCipherKey, k.SendCipherKey)
		for i := range k.SendHMACKey {
			k.SendHMACKey[i] = 0x22
		}
		copy(k.RecvHMACKey, k.SendHMACKey)
		return k
	}
	initial, err := NewDataChannel(mk(), CipherAES128GCM, AuthSHA256, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	rekeyed, err := NewDataChannel(mk(), CipherAES128GCM, AuthSHA256, 7, 1)
	if err != nil {
		t.Fatal(err)
	}
	client.installDataChannel(initial)
	// Production order: the control epoch advances, AUTH_PENDING is parsed
	// after KM2 but BEFORE the matching data channel is installed.
	client.control.AdoptKeyID(1)
	client.applyAuthPendingTimeout(&PushReply{AuthPendingTimeout: 300 * time.Second})
	client.installDataChannel(rekeyed)
	// Simulate the independent auth_deferred_expire selection window elapsing
	// while the advertised pending deadline remains far in the future.
	client.dataLock.Lock()
	client.outboundStart = time.Now().Add(-authDeferredExpire - time.Second)
	deferred := client.deferredUntil
	client.dataLock.Unlock()
	if time.Until(deferred) < 290*time.Second {
		t.Fatalf("epoch install discarded AUTH_PENDING deadline: %v", deferred)
	}

	// AUTH_PENDING remains staged on the active epoch, but it must not extend
	// old-key transmission beyond the independent selection window.
	if err := client.writeDataPacket(context.Background(), []byte{0x45, 0, 0, 20}, false); err != nil {
		t.Fatal(err)
	}
	pkt, err := serverIO.ReadPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, keyID := parseOpcodeKeyID(pkt[0]); keyID != 1 {
		t.Fatalf("AUTH_PENDING extended outbound selection: got key=%d want=1", keyID)
	}
}

// TestRetiringWindowAnchoredAtAcceptedSoftReset verifies the optional probe
// of the previous TLS epoch cannot shift the old key's transition lifetime.
// The absolute deadline captured when the reset is accepted must survive
// unchanged through renegotiate and data-channel installation.
func TestRetiringWindowAnchoredAtAcceptedSoftReset(t *testing.T) {
	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{TransitionWindow: 10 * time.Second}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	initial := &DataChannel{keyID: 0}
	rekeyed := &DataChannel{keyID: 1}
	client.installDataChannel(initial)

	// Model a reset accepted one token probe ago while a previous TLS epoch was
	// still finishing. Retrieving the stashed reset later must not restart its
	// transition lifetime.
	acceptedAt := time.Now().Add(-tokenPushReadTimeout)
	reset := &ControlPacket{receivedAt: acceptedAt}
	anchored := client.retiringWindowDeadline(reset)
	if want := acceptedAt.Add(client.transitionWindow()); !anchored.Equal(want) {
		t.Fatalf("stashed reset shifted transition deadline: got=%v want=%v", anchored, want)
	}
	client.controlConn = NewControlConn(client.control)
	client.cancel()
	if err := client.renegotiate(nil, anchored); err == nil {
		t.Fatal("renegotiate unexpectedly succeeded with a canceled run context")
	}

	client.installDataChannel(rekeyed)
	client.dataLock.RLock()
	got := client.retiringExpiry
	pending := client.pendingRetiringExpiry
	client.dataLock.RUnlock()
	if !got.Equal(anchored) {
		t.Fatalf("transition window shifted after accepted reset: got=%v want=%v", got, anchored)
	}
	if !pending.IsZero() {
		t.Fatalf("installed transition deadline remained pending: %v", pending)
	}
}

func TestExplicitZeroTransitionWindow(t *testing.T) {
	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{TransitionWindowSet: true}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if got := client.transitionWindow(); got != 0 {
		t.Fatalf("explicit zero transition window became %v", got)
	}

	defaultIO, _ := newMemoryPacketPair()
	defaultClient, err := NewClient(&ClientConfig{}, defaultIO)
	if err != nil {
		t.Fatal(err)
	}
	defer defaultClient.Close()
	if got := defaultClient.transitionWindow(); got != transitionWindow {
		t.Fatalf("omitted transition window = %v, want %v", got, transitionWindow)
	}
}

// TestRetiringExpiryForcesOutboundPromotion verifies the previous epoch is
// never selected for transmit after its transition lifetime, even when there
// is no peer evidence and the AUTH_PENDING deadline is still in the future.
func TestRetiringExpiryForcesOutboundPromotion(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	mk := func(fill byte) *KeyMaterial {
		k := &KeyMaterial{
			SendCipherKey: make([]byte, 16),
			SendHMACKey:   make([]byte, maxHMACKeyLength),
			RecvCipherKey: make([]byte, 16),
			RecvHMACKey:   make([]byte, maxHMACKeyLength),
		}
		for i := range k.SendCipherKey {
			k.SendCipherKey[i] = fill
		}
		copy(k.RecvCipherKey, k.SendCipherKey)
		for i := range k.SendHMACKey {
			k.SendHMACKey[i] = fill + 1
		}
		copy(k.RecvHMACKey, k.SendHMACKey)
		return k
	}
	initial, err := NewDataChannel(mk(0x11), CipherAES128GCM, AuthSHA256, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	rekeyed, err := NewDataChannel(mk(0x22), CipherAES128GCM, AuthSHA256, 7, 1)
	if err != nil {
		t.Fatal(err)
	}
	client.installDataChannel(initial)
	client.config.TransitionWindow = 10 * time.Second
	client.installDataChannel(rekeyed)
	client.dataLock.Lock()
	client.retiringExpiry = time.Now().Add(-time.Millisecond)
	client.outboundStart = time.Now() // independent 60s window has not elapsed
	client.dataLock.Unlock()

	if err := client.writeDataPacket(context.Background(), []byte{0x45, 0, 0, 20}, false); err != nil {
		t.Fatal(err)
	}
	pkt, err := serverIO.ReadPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, keyID := parseOpcodeKeyID(pkt[0]); keyID != 1 {
		t.Fatalf("expired retiring key remained outbound: got=%d want=1", keyID)
	}
}

// TestStandaloneAuthPendingKeepsTokenProbeShort verifies dynamically observed
// AUTH_PENDING updates the transport deadline but does not hold data-epoch
// installation until the full advertised timeout. A later token update is
// consumed by the established parked-TLS watcher.
func TestStandaloneAuthPendingKeepsTokenProbeShort(t *testing.T) {
	conn := &chunkConn{
		data: [][]byte{
			[]byte("AUTH_PENDING,timeout 60\x00"),
			nil,
			[]byte("PUSH_REPLY,auth-token SESS_ID_late\x00"),
		},
		errs: []error{nil, os.ErrDeadlineExceeded, nil},
	}
	reply, rest, err := readTokenPushReply(conn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if conn.idx != 2 {
		t.Fatalf("standalone AUTH_PENDING waited for optional final push: reads=%d", conn.idx)
	}
	if reply == nil || reply.AuthPendingTimeout != 60*time.Second || reply.HasPushReply {
		t.Fatalf("standalone AUTH_PENDING metadata lost: %#v", reply)
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected rest: %q", rest)
	}
	if len(conn.operationDeadlines) == 0 ||
		time.Until(conn.operationDeadlines[0]) < 50*time.Second {
		t.Fatalf("AUTH_PENDING transport deadline not propagated: %v", conn.operationDeadlines)
	}
}

// TestTakePushReplyContinuation verifies the review point 2: an intermediate
// push-continuation 2 segment is not a complete reply, and the final segment
// merges repeatable fields (routes / dns) across segments in wire order.
// TestStandaloneAuthPendingDoesNotCompletePush verifies AUTH_PENDING updates
// timeout state but does not complete PUSH parsing before a final PUSH_REPLY.
// TestReadTokenPushReplyPromotesDynamicWait verifies dynamically discovered
// push-continuation state upgrades the active wait policy across a short
// timeout until the final segment arrives. Standalone AUTH_PENDING is covered
// separately: it updates deadline metadata without extending the token probe.
func TestReadTokenPushReplyPromotesDynamicWait(t *testing.T) {
	t.Run("push-continuation", func(t *testing.T) {
		conn := &chunkConn{
			data: [][]byte{
				[]byte("PUSH_REPLY,route 10.1.0.0 255.255.0.0,push-continuation 2\x00"),
				nil,
				[]byte("PUSH_REPLY,route 10.2.0.0 255.255.0.0\x00"),
			},
			errs: []error{nil, os.ErrDeadlineExceeded, nil},
		}
		reply, _, err := readTokenPushReply(conn, nil)
		if err != nil {
			t.Fatal(err)
		}
		if conn.idx != 3 {
			t.Fatalf("reader returned before final continuation: reads=%d", conn.idx)
		}
		if reply == nil || len(reply.Routes) != 2 ||
			reply.Routes[0].String() != "10.1.0.0/16" || reply.Routes[1].String() != "10.2.0.0/16" {
			t.Fatalf("continuation state lost: %#v", reply)
		}
	})
}

// TestReadTokenPushReplyExtendsReliableACKDeadline reproduces the dynamic
// AUTH_PENDING path on an in-memory reliable ControlConn. AUTH_PENDING is
// already decoded when the original operation deadline expires; the final
// reliable packet still needs an ACK write before its TLS payload can be
// delivered. The helper must therefore extend both deadline directions as
// soon as it processes AUTH_PENDING.
func TestReadTokenPushReplyExtendsReliableACKDeadline(t *testing.T) {
	clientControl, serverControl := newTestChannels(t)
	clientControl.SetRemoteSessionID(serverControl.LocalSessionID())
	serverControl.SetRemoteSessionID(clientControl.LocalSessionID())
	conn := NewControlConn(clientControl)
	// Put AUTH_PENDING directly in the TLS adapter's already-decoded buffer,
	// then reproduce the stale deadline left by the 30-second rekey context.
	// The next reliable packet still needs a write-side ACK before delivery.
	conn.UnsafeFeed([]byte("AUTH_PENDING,timeout 1\x00"))
	if err := conn.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := serverControl.Send(context.Background(), PControlV1,
		[]byte("PUSH_REPLY,auth-token SESS_ID_after_deadline\x00")); err != nil {
		t.Fatal(err)
	}

	reply, rest, err := readTokenPushReply(conn, nil)
	if err != nil {
		t.Fatalf("extended read could not deliver final reliable packet: %v", err)
	}
	if reply == nil || reply.AuthTokenPass != "SESS_ID_after_deadline" {
		t.Fatalf("final PUSH_REPLY not delivered: %#v", reply)
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected rest: %q", rest)
	}
}

// TestAuthPendingDeadlineAnchoredAtTLSEstablishment verifies a delayed
// AUTH_PENDING and the final PUSH_REPLY do not restart the reference timeout,
// which is measured from key_state.established.
func TestAuthPendingDeadlineAnchoredAtTLSEstablishment(t *testing.T) {
	pending, _, ok := takePushReply([]byte("AUTH_PENDING,timeout 1\x00"))
	if ok || pending == nil || !pending.authPendingUntil.IsZero() {
		t.Fatalf("AUTH_PENDING intermediate state malformed: %#v", pending)
	}
	establishedAt := time.Now().Add(-150 * time.Millisecond)
	anchorAuthPendingDeadline(pending, establishedAt)
	wantDeadline := establishedAt.Add(time.Second)
	if !pending.authPendingUntil.Equal(wantDeadline) {
		t.Fatalf("AUTH_PENDING deadline = %v, want %v", pending.authPendingUntil, wantDeadline)
	}

	final, err := parsePushReplyInner("PUSH_REPLY,auth-token SESS_ID_anchored")
	if err != nil {
		t.Fatal(err)
	}
	merged := mergePushReply(pending, final)
	if !merged.authPendingUntil.Equal(wantDeadline) {
		t.Fatalf("AUTH_PENDING deadline moved during final merge: got %v, want %v",
			merged.authPendingUntil, wantDeadline)
	}

	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.controlEstablishedAt = establishedAt
	client.applyAuthPendingTimeout(merged)
	client.dataLock.RLock()
	staged := client.pendingDeferredUntil
	client.dataLock.RUnlock()
	if !staged.Equal(wantDeadline) {
		t.Fatalf("AUTH_PENDING timeout restarted after final PUSH_REPLY: got %v, want %v",
			staged, wantDeadline)
	}
}

// TestAuthPendingUpdateCanShortenDeadline verifies a later AUTH_PENDING for
// the same key replaces, rather than monotonically extends, the staged and
// active data-epoch deadline, effective control deadline, transport deadline,
// and token reader's active operation deadline.
func TestAuthPendingUpdateCanShortenDeadline(t *testing.T) {
	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.controlConn = NewControlConn(client.control)

	long, err := parseAuthPendingTimeout("AUTH_PENDING,timeout 60")
	if err != nil {
		t.Fatal(err)
	}
	short, err := parseAuthPendingTimeout("AUTH_PENDING,timeout 1")
	if err != nil {
		t.Fatal(err)
	}
	client.applyAuthPendingTimeout(long)
	client.applyAuthPendingTimeout(short)
	client.control.mu.Lock()
	transportRead := client.control.readDeadline
	transportWrite := client.control.writeDeadline
	client.control.mu.Unlock()
	if !transportRead.Equal(short.authPendingUntil) || !transportWrite.Equal(short.authPendingUntil) {
		t.Fatalf("later AUTH_PENDING did not replace transport deadline: read=%v write=%v want=%v",
			transportRead, transportWrite, short.authPendingUntil)
	}
	client.dataLock.RLock()
	staged := client.pendingDeferredUntil
	client.dataLock.RUnlock()
	if !staged.Equal(short.authPendingUntil) {
		t.Fatalf("later AUTH_PENDING did not shorten staged deadline: got=%v want=%v",
			staged, short.authPendingUntil)
	}
	fallback := time.Now().Add(30 * time.Second)
	if effective := client.effectiveControlDeadline(fallback); !effective.Equal(short.authPendingUntil) {
		t.Fatalf("effective deadline retained longer fallback: got=%v want=%v",
			effective, short.authPendingUntil)
	}

	// Install the matching epoch and verify the shortened metadata deadline is
	// transferred to that epoch without affecting the independent outbound
	// selection window.
	mk := func(fill byte) *KeyMaterial {
		k := &KeyMaterial{
			SendCipherKey: make([]byte, 16),
			SendHMACKey:   make([]byte, maxHMACKeyLength),
			RecvCipherKey: make([]byte, 16),
			RecvHMACKey:   make([]byte, maxHMACKeyLength),
		}
		for i := range k.SendCipherKey {
			k.SendCipherKey[i] = fill
		}
		copy(k.RecvCipherKey, k.SendCipherKey)
		for i := range k.SendHMACKey {
			k.SendHMACKey[i] = fill + 1
		}
		copy(k.RecvHMACKey, k.SendHMACKey)
		return k
	}
	initial, err := NewDataChannel(mk(0x11), CipherAES128GCM, AuthSHA256, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	active, err := NewDataChannel(mk(0x22), CipherAES128GCM, AuthSHA256, 7, 1)
	if err != nil {
		t.Fatal(err)
	}
	client.installDataChannel(initial)
	client.control.AdoptKeyID(1)
	client.applyAuthPendingTimeout(long)
	client.applyAuthPendingTimeout(&PushReply{
		AuthPendingTimeout: time.Second,
		authPendingUntil:   time.Now().Add(-time.Millisecond),
	})
	client.installDataChannel(active)
	client.dataLock.RLock()
	activeDeferred := client.deferredUntil
	activeOutbound := client.outboundKey
	client.dataLock.RUnlock()
	if !activeDeferred.Before(time.Now()) {
		t.Fatalf("shorter AUTH_PENDING deadline not transferred to active epoch: %v", activeDeferred)
	}
	if activeOutbound != initial {
		t.Fatal("AUTH_PENDING metadata changed independent outbound selection")
	}

	conn := &chunkConn{
		data: [][]byte{
			[]byte("AUTH_PENDING,timeout 60\x00"),
			[]byte("AUTH_PENDING,timeout 1\x00"),
			[]byte("PUSH_REPLY,auth-token SESS_ID_short\x00"),
		},
	}
	if _, _, err := readTokenPushReply(conn, nil); err != nil {
		t.Fatal(err)
	}
	if len(conn.operationDeadlines) < 2 {
		t.Fatalf("AUTH_PENDING updates not propagated: %v", conn.operationDeadlines)
	}
	first := conn.operationDeadlines[0]
	second := conn.operationDeadlines[1]
	if !second.Before(first) {
		t.Fatalf("reader ignored shorter AUTH_PENDING: first=%v second=%v", first, second)
	}
}

func TestConsumeParkedRekeyPushFeedsControlConnInOrder(t *testing.T) {
	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.controlConn = NewControlConn(client.control)
	client.control.mu.Lock()
	client.control.parkedTLS = [][]byte{[]byte("first"), []byte("second")}
	client.control.mu.Unlock()
	if err := client.consumeParkedRekeyPush(); err != nil {
		t.Fatal(err)
	}
	client.controlConn.mu.Lock()
	got := append([]byte(nil), client.controlConn.readBuf...)
	client.controlConn.mu.Unlock()
	if string(got) != "firstsecond" {
		t.Fatalf("parked TLS bytes = %q, want %q", got, "firstsecond")
	}
	client.control.mu.Lock()
	remaining := len(client.control.parkedTLS)
	client.control.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("parked TLS payloads not drained: %d", remaining)
	}
}

// TestConsumeParkedRekeyPushClearsDeadline verifies a successful standalone
// parked push cannot leave its AUTH_PENDING operation deadline on the
// established connection's next waitForSoftReset cycle.
func TestConsumeParkedRekeyPushClearsDeadline(t *testing.T) {
	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.push = &PushReply{PeerID: 7}
	client.controlConn = NewControlConn(client.control)
	client.leftoverTLS = []byte("AUTH_PENDING,timeout 1\x00" +
		"PUSH_REPLY,auth-token SESS_ID_parked\x00")

	if err := client.consumeParkedRekeyPush(); err != nil {
		t.Fatal(err)
	}
	client.control.mu.Lock()
	readDeadline := client.control.readDeadline
	writeDeadline := client.control.writeDeadline
	client.control.mu.Unlock()
	if !readDeadline.IsZero() || !writeDeadline.IsZero() {
		t.Fatalf("successful parked push consume leaked operation deadline: read=%v write=%v",
			readDeadline, writeDeadline)
	}
	if client.authPass != "SESS_ID_parked" {
		t.Fatalf("parked auth token was not consumed: %q", client.authPass)
	}
}

// TestConsumeRekeyPushRejectsContinuationDiscoveredByReader verifies an
// intermediate continuation first seen inside the final probe remains marked
// incomplete when that probe reaches its deadline without a final segment.
func TestConsumeRekeyPushRejectsContinuationDiscoveredByReader(t *testing.T) {
	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.push = &PushReply{PeerID: 7, AuthTokenPass: "SESS_ID_old"}
	conn := &chunkConn{}
	reader := func(got pushReadConn, leftover []byte, _ ...time.Time) (*PushReply, []byte, error) {
		if got != conn {
			t.Fatalf("reader received wrong connection: %T", got)
		}
		if len(leftover) != 0 {
			t.Fatalf("unexpected initial leftover: %q", leftover)
		}
		return &PushReply{
			PeerID:           PeerIDUnset,
			HasPushReply:     true,
			PushContinuation: 2,
			Routes:           []netip.Prefix{netip.MustParsePrefix("10.9.0.0/16")},
		}, nil, nil
	}

	err = client.consumeRekeyPushFrom(conn, reader)
	if err == nil || !strings.Contains(err.Error(), "continued push reply incomplete") {
		t.Fatalf("reader-discovered continuation returned success: %v", err)
	}
	if !client.pushContinuationPending {
		t.Fatal("reader-discovered continuation state was not persisted")
	}
	if client.pushPending == nil || client.pushPending.PushContinuation != 2 ||
		len(client.pushPending.Routes) != 1 {
		t.Fatalf("reader-discovered partial push was not retained: %#v", client.pushPending)
	}
	if client.push.AuthTokenPass != "SESS_ID_old" || len(client.push.Routes) != 0 {
		t.Fatalf("partial continuation was committed to active push: %#v", client.push)
	}
}

// TestConsumeRekeyPushAllowsAuthPendingWithoutFinalPush verifies deferred
// authentication does not require the optional token-only PUSH_REPLY. A server
// without auth-gen-token can send AUTH_PENDING, authenticate the new key, and
// generate data keys without sending any further push message.
func TestConsumeRekeyPushAllowsAuthPendingWithoutFinalPush(t *testing.T) {
	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	mk := func(fill byte) *KeyMaterial {
		k := &KeyMaterial{
			SendCipherKey: make([]byte, 16),
			SendHMACKey:   make([]byte, maxHMACKeyLength),
			RecvCipherKey: make([]byte, 16),
			RecvHMACKey:   make([]byte, maxHMACKeyLength),
		}
		for i := range k.SendCipherKey {
			k.SendCipherKey[i] = fill
		}
		copy(k.RecvCipherKey, k.SendCipherKey)
		for i := range k.SendHMACKey {
			k.SendHMACKey[i] = fill + 1
		}
		copy(k.RecvHMACKey, k.SendHMACKey)
		return k
	}
	initial, err := NewDataChannel(mk(0x11), CipherAES128GCM, AuthSHA256, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	rekeyed, err := NewDataChannel(mk(0x22), CipherAES128GCM, AuthSHA256, 7, 1)
	if err != nil {
		t.Fatal(err)
	}
	client.installDataChannel(initial)
	client.control.AdoptKeyID(1)
	client.push = &PushReply{
		PeerID:        7,
		Cipher:        CipherAES128GCM,
		AuthTokenPass: "",
		Routes:        []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")},
	}
	conn := &chunkConn{}
	pending, err := parseAuthPendingTimeout("AUTH_PENDING,timeout 1")
	if err != nil {
		t.Fatal(err)
	}
	reader := func(got pushReadConn, leftover []byte, _ ...time.Time) (*PushReply, []byte, error) {
		if got != conn {
			t.Fatalf("reader received wrong connection: %T", got)
		}
		if len(leftover) != 0 {
			t.Fatalf("unexpected initial leftover: %q", leftover)
		}
		return pending, nil, nil
	}

	if err := client.consumeRekeyPushFrom(conn, reader); err != nil {
		t.Fatalf("standalone AUTH_PENDING required a final PUSH_REPLY: %v", err)
	}
	if client.push.PeerID != 7 || client.push.Cipher != CipherAES128GCM ||
		len(client.push.Routes) != 1 || client.push.Routes[0].String() != "10.8.0.0/24" {
		t.Fatalf("cached push changed without a final PUSH_REPLY: %#v", client.push)
	}
	if client.pushPending != nil || client.pushContinuationPending {
		t.Fatalf("standalone AUTH_PENDING left incomplete push state: pending=%#v continuation=%v",
			client.pushPending, client.pushContinuationPending)
	}
	client.dataLock.RLock()
	staged := client.pendingDeferredUntil
	stagedKey := client.pendingDeferredKeyID
	stagedSet := client.pendingDeferredSet
	client.dataLock.RUnlock()
	if !stagedSet || stagedKey != client.control.KeyID() || !staged.Equal(pending.authPendingUntil) {
		t.Fatalf("AUTH_PENDING epoch deadline not retained: set=%v key=%d deadline=%v want=%v",
			stagedSet, stagedKey, staged, pending.authPendingUntil)
	}
	client.installDataChannel(rekeyed)
	client.dataLock.RLock()
	active := client.data
	outbound := client.outboundKey
	deferred := client.deferredUntil
	client.dataLock.RUnlock()
	if active != rekeyed || outbound != initial {
		t.Fatalf("valid deferred epoch was not installable: active=%p outbound=%p", active, outbound)
	}
	if !deferred.Equal(pending.authPendingUntil) {
		t.Fatalf("staged deferred deadline not transferred to installed epoch: got=%v want=%v",
			deferred, pending.authPendingUntil)
	}
}

func TestStandaloneAuthPendingDoesNotCompletePush(t *testing.T) {
	bareReply, _, bareOK := takePushReply([]byte("AUTH_PENDING\x00"))
	if bareOK {
		t.Fatal("bare AUTH_PENDING alone completed PUSH parsing")
	}
	if bareReply == nil || bareReply.AuthPendingTimeout != authDeferredExpire {
		t.Fatalf("bare AUTH_PENDING did not receive default timeout: %#v", bareReply)
	}

	pending := []byte("AUTH_PENDING,timeout 300\x00")
	reply, rest, ok := takePushReply(pending)
	if ok {
		t.Fatal("AUTH_PENDING alone completed PUSH parsing")
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected rest: %q", rest)
	}
	if reply == nil || reply.AuthPendingTimeout != 300*time.Second {
		t.Fatalf("AUTH_PENDING timeout not parsed: %#v", reply)
	}

	coalesced := []byte("AUTH_PENDING,timeout 300\x00" +
		"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0\x00")
	reply, _, ok = takePushReply(coalesced)
	if !ok {
		t.Fatal("final PUSH_REPLY did not complete parsing")
	}
	if reply.AuthPendingTimeout != 300*time.Second {
		t.Fatalf("AUTH_PENDING timeout lost during merge: got %v, want 5m", reply.AuthPendingTimeout)
	}
}

// TestPushContinuationWireOrderAndCrossCall verifies repeatable fields retain
// wire order and an intermediate segment survives until a final segment in a
// later consumeRekeyPush call.
func TestPushContinuationWireOrderAndCrossCall(t *testing.T) {
	full := []byte("PUSH_REPLY,route 10.1.0.0 255.255.0.0,dhcp-option DNS 1.1.1.1,data-ciphers AES-256-GCM,push-continuation 2\x00" +
		"PUSH_REPLY,route 10.2.0.0 255.255.0.0,dhcp-option DNS 8.8.8.8,data-ciphers AES-128-GCM\x00")
	reply, _, ok := takePushReply(full)
	if !ok {
		t.Fatal("coalesced continuation did not complete")
	}
	if got := []string{reply.Routes[0].String(), reply.Routes[1].String()}; got[0] != "10.1.0.0/16" || got[1] != "10.2.0.0/16" {
		t.Fatalf("route wire order changed: %v", got)
	}
	if got := []string{reply.DNS[0].String(), reply.DNS[1].String()}; got[0] != "1.1.1.1" || got[1] != "8.8.8.8" {
		t.Fatalf("DNS wire order changed: %v", got)
	}
	if len(reply.DataCiphers) != 2 || reply.DataCiphers[0] != "AES-256-GCM" || reply.DataCiphers[1] != "AES-128-GCM" {
		t.Fatalf("cipher wire order changed: %v", reply.DataCiphers)
	}

	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{Username: "u", Password: "p"}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.push = &PushReply{PeerID: 7}
	client.leftoverTLS = []byte("PUSH_REPLY,route 10.1.0.0 255.255.0.0,push-continuation 2\x00")
	if err := client.consumeRekeyPush(); err != nil {
		t.Fatal(err)
	}
	if client.pushPending == nil || len(client.pushPending.Routes) != 1 {
		t.Fatalf("intermediate continuation not retained: %#v", client.pushPending)
	}
	client.leftoverTLS = []byte("PUSH_REPLY,route 10.2.0.0 255.255.0.0\x00")
	if err := client.consumeRekeyPush(); err != nil {
		t.Fatal(err)
	}
	if len(client.push.Routes) != 2 || client.push.Routes[0].String() != "10.1.0.0/16" || client.push.Routes[1].String() != "10.2.0.0/16" {
		t.Fatalf("intermediate continuation discarded across calls: %v", client.push.Routes)
	}
}

func TestTakePushReplyContinuation(t *testing.T) {
	// Only an intermediate segment: not complete.
	intermediate := []byte("PUSH_REPLY,route 10.2.0.0 255.255.0.0,push-continuation 2\x00")
	reply, _, ok := takePushReply(intermediate)
	if ok {
		t.Fatal("intermediate push-continuation segment treated as complete")
	}
	if reply == nil || len(reply.Routes) != 1 {
		t.Fatalf("intermediate segment routes not parsed: %#v", reply)
	}
	// Intermediate + final in one buffer: complete, routes/dns merged.
	full := []byte("PUSH_REPLY,route 10.2.0.0 255.255.0.0,push-continuation 2\x00" +
		"PUSH_REPLY,dhcp-option DNS 8.8.8.8,ifconfig 10.8.0.2 255.255.255.0,route 10.3.0.0 255.255.0.0\x00")
	reply, _, ok = takePushReply(full)
	if !ok {
		t.Fatal("final push-continuation segment not complete")
	}
	if len(reply.Routes) != 2 {
		t.Fatalf("continuation routes lost: %v", reply.Routes)
	}
	if len(reply.DNS) != 1 || reply.DNS[0].String() != "8.8.8.8" {
		t.Fatalf("continuation dns lost: %v", reply.DNS)
	}
	if len(reply.Prefixes) != 1 {
		t.Fatalf("continuation ifconfig lost: %v", reply.Prefixes)
	}
}

func TestOutboundKeyStaysLameDuckUntilPeerEvidence(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{Username: "u", Password: "p"}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	mkKeys := func() *KeyMaterial {
		k := &KeyMaterial{
			SendCipherKey: make([]byte, 16),
			SendHMACKey:   make([]byte, maxHMACKeyLength),
			RecvCipherKey: make([]byte, 16),
			RecvHMACKey:   make([]byte, maxHMACKeyLength),
		}
		for i := range k.SendCipherKey {
			k.SendCipherKey[i] = 0x11
		}
		// Identical send/recv keys so a locally-encrypted packet decrypts
		// through the peer path (the direction split is irrelevant here).
		copy(k.RecvCipherKey, k.SendCipherKey)
		for i := range k.SendHMACKey {
			k.SendHMACKey[i] = 0x22
		}
		copy(k.RecvHMACKey, k.SendHMACKey)
		return k
	}

	initial, err := NewDataChannel(mkKeys(), CipherAES128GCM, AuthSHA256, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	rekeyed, err := NewDataChannel(mkKeys(), CipherAES128GCM, AuthSHA256, 7, 1)
	if err != nil {
		t.Fatal(err)
	}
	client.installDataChannel(initial)
	// Activate the first epoch: outbound switches to it immediately.
	if err := client.writeDataPacket(context.Background(), []byte{0x45, 0, 0, 20}, false); err != nil {
		t.Fatal(err)
	}
	// Drain that first packet.
	if _, err := serverIO.ReadPacket(context.Background()); err != nil {
		t.Fatal(err)
	}
	client.installDataChannel(rekeyed)

	// First outbound packet after the rekey must still use the old key ID 0
	// (deferred auth: peer has not yet activated key ID 1).
	if err := client.writeDataPacket(context.Background(), []byte{0x45, 0, 0, 20}, false); err != nil {
		t.Fatal(err)
	}
	pkt, err := serverIO.ReadPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, keyID := parseOpcodeKeyID(pkt[0]); keyID != 0 {
		t.Fatalf("outbound key ID after rekey = %d; want 0 (lame duck)", keyID)
	}

	// Simulate the peer activating the new key: encrypt a data packet with the
	// new key and decrypt it through the client, which latches newKeyEvidence.
	peerPkt, err := rekeyed.Encrypt([]byte{0x45, 0, 0, 20})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.decryptDataPacket(peerPkt); err != nil {
		t.Fatalf("decrypt new-key packet: %v", err)
	}

	// After evidence, outbound switches to key ID 1.
	if err := client.writeDataPacket(context.Background(), []byte{0x45, 0, 0, 20}, false); err != nil {
		t.Fatal(err)
	}
	pkt, err = serverIO.ReadPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, keyID := parseOpcodeKeyID(pkt[0]); keyID != 1 {
		t.Fatalf("outbound key ID after evidence = %d; want 1", keyID)
	}
}

// TestMergePushReplyContinuation verifies multi-segment PUSH_REPLY
// (push-continuation) merging carries every field across segments.
func TestMergePushReplyContinuation(t *testing.T) {
	seg1 := &PushReply{
		DNS:    []netip.Addr{netip.MustParseAddr("8.8.8.8")},
		PeerID: 7,
		Cipher: "AES-128-GCM",
	}
	seg2 := &PushReply{
		PeerID:   PeerIDUnset,
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.8.0.2/24")},
		Routes:   []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1")},
		Redirect: true,
	}
	merged := mergePushReply(seg1, seg2)
	if len(merged.DNS) != 1 || merged.DNS[0] != seg1.DNS[0] {
		t.Fatalf("DNS not inherited: %v", merged.DNS)
	}
	if merged.PeerID != 7 {
		t.Fatalf("PeerID not inherited: %d", merged.PeerID)
	}
	if merged.Cipher != "AES-128-GCM" {
		t.Fatalf("Cipher not inherited: %q", merged.Cipher)
	}
	if len(merged.Prefixes) != 1 || len(merged.Routes) != 1 {
		t.Fatalf("seg2 fields missing: prefixes=%v routes=%v", merged.Prefixes, merged.Routes)
	}
	if !merged.Redirect {
		t.Fatal("Redirect not inherited")
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

// TestTakePushReplyRequiresTerminator verifies a PUSH_REPLY is not committed
// until its NUL terminator arrives: a fragment ending after "ifconfig" must
// not lose later route / DNS / cipher / token options (matching the reference
// client, which parses the full message).
func TestTakePushReplyRequiresTerminator(t *testing.T) {
	// Fragment ending after ifconfig, no terminator: must not be accepted.
	frag := []byte("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0")
	if _, _, ok := takePushReply(frag); ok {
		t.Fatal("unterminated PUSH_REPLY was accepted")
	}
	// Once the terminator (and a later option) arrives, it is parsed fully.
	full := append(append([]byte(nil), frag...), []byte(",route-gateway 10.8.0.1\x00")...)
	reply, rest, ok := takePushReply(full)
	if !ok {
		t.Fatal("terminated PUSH_REPLY was not accepted")
	}
	if len(reply.Prefixes) != 1 {
		t.Fatalf("prefixes not parsed: %v", reply.Prefixes)
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected leftover: %q", rest)
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
func TestInitialHandshakeRetransmitsLostClientHello(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	_, caPEM := newTestTLSServerCertificate(t)
	config := &ClientConfig{
		Proto:      ProtoUDP,
		CA:         caPEM,
		Cipher:     CipherAES128GCM,
		Auth:       AuthSHA256,
		Username:   "user",
		Password:   "pass",
		RemoteHost: "server",
		RemotePort: 1194,
	}
	client, err := NewClient(config, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	handshakeErr := make(chan error, 1)
	go func() {
		_, err := client.Handshake(ctx)
		handshakeErr <- err
	}()

	resetRaw, err := serverIO.ReadPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reset, _, _, err := DecodeControlPacket(nil, resetRaw)
	if err != nil {
		t.Fatal(err)
	}
	var serverID SessionID
	copy(serverID[:], []byte("server01"))
	serverControl := NewControlChannel(serverIO, nil, serverID)
	serverControl.SetRemoteSessionID(reset.LocalSession)
	serverControl.QueueAck(reset.MessageID)
	if _, err := serverControl.Send(ctx, PControlHardResetServerV2, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-handshakeErr:
		t.Fatalf("handshake stopped before ClientHello: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	var first *ControlPacket
	for first == nil {
		raw, err := serverIO.ReadPacket(ctx)
		if err != nil {
			t.Fatal(err)
		}
		packet, _, _, err := DecodeControlPacket(nil, raw)
		if err != nil {
			t.Fatal(err)
		}
		if packet.Opcode == PControlV1 {
			first = packet
		}
	}

	for {
		raw, err := serverIO.ReadPacket(ctx)
		if err != nil {
			t.Fatal(err)
		}
		packet, _, _, err := DecodeControlPacket(nil, raw)
		if err != nil {
			t.Fatal(err)
		}
		if packet.Opcode == PControlV1 && packet.MessageID == first.MessageID {
			if !bytes.Equal(packet.Payload, first.Payload) {
				t.Fatal("retransmitted ClientHello payload changed")
			}
			break
		}
	}
	cancel()
	if err := <-handshakeErr; err == nil {
		t.Fatal("incomplete test handshake unexpectedly succeeded")
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
		Proto:       ProtoUDP,
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
	// Start the UDP control retransmission loop exactly like renegotiate().
	stop := client.retransmitControl(ctx)
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
func TestMergePushReplyPreservesContinuationAcrossAuthPending(t *testing.T) {
	continued := &PushReply{HasPushReply: true, PushContinuation: 2}
	pending := &PushReply{hasAuthPending: true, AuthPendingTimeout: time.Second}
	merged := mergePushReply(continued, pending)
	if merged.PushContinuation != 2 || !merged.HasPushReply {
		t.Fatalf("AUTH_PENDING lost continuation state: %+v", merged)
	}
	final := mergePushReply(merged, &PushReply{HasPushReply: true})
	if final.PushContinuation != 0 {
		t.Fatalf("final PUSH_REPLY retained continuation %d", final.PushContinuation)
	}
}

func TestReadServerKeyMethodRejectsInvalidPrefixImmediately(t *testing.T) {
	packet := make([]byte, 4+1+keySourceRandomSize*2)
	packet[3] = 1
	packet[4] = KeyMethod2
	conn := &chunkConn{data: [][]byte{packet}}
	client := &Client{control: &ControlChannel{}}
	_, err := client.readServerKeyMethodFrom(context.Background(), conn)
	if err == nil || !strings.Contains(err.Error(), "invalid key method 2 prefix") {
		t.Fatalf("invalid prefix returned %v", err)
	}
	if conn.idx != 1 {
		t.Fatalf("invalid prefix triggered %d reads, want 1", conn.idx)
	}
}

func TestReadPushReplyCanceledBeforeRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn := &chunkConn{data: [][]byte{[]byte("must not read")}}
	client := &Client{control: &ControlChannel{}}
	if _, err := client.readPushReplyFrom(ctx, conn); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled push read returned %v", err)
	}
	if conn.idx != 0 {
		t.Fatalf("canceled push reader consumed %d chunks", conn.idx)
	}
}

func TestOutboundPromotionWindowAnchoredAtSoftReset(t *testing.T) {
	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{TransitionWindow: time.Minute, TransitionWindowSet: true}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	mk := func(keyID uint8) *DataChannel {
		keys := &KeyMaterial{
			SendCipherKey: bytes.Repeat([]byte{0x11}, 16),
			SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
			RecvCipherKey: bytes.Repeat([]byte{0x11}, 16),
			RecvHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		}
		data, err := NewDataChannel(keys, CipherAES128GCM, AuthSHA256, 7, keyID)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	client.installDataChannel(mk(0))
	acceptedAt := time.Now().Add(-30 * time.Second)
	client.stageRetiringWindow(acceptedAt.Add(time.Minute))
	client.installDataChannel(mk(1))
	if delta := client.outboundStart.Sub(acceptedAt); delta < -time.Millisecond || delta > time.Millisecond {
		t.Fatalf("outbound promotion start = %v, want %v", client.outboundStart, acceptedAt)
	}
}

func TestParsePushRejectsMalformedCredentialAndContinuation(t *testing.T) {
	for _, message := range []string{
		"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,auth-token SESS_ID_ok,auth-token-user !!!",
		"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,push-continuation nope",
		"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,push-continuation 3",
	} {
		if _, err := ParsePushReply(message); err == nil {
			t.Fatalf("malformed pushed field accepted: %q", message)
		}
	}
}

type temporaryControlWriteError struct{}

func (temporaryControlWriteError) Error() string   { return "temporary control write" }
func (temporaryControlWriteError) Timeout() bool   { return false }
func (temporaryControlWriteError) Temporary() bool { return true }

type retransmitTestPacketIO struct {
	mu      sync.Mutex
	writes  int
	first   error
	second  error
	retried chan struct{}
	once    sync.Once
}

func (p *retransmitTestPacketIO) ReadPacket(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (p *retransmitTestPacketIO) WritePacket(context.Context, []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.writes++
	if p.writes == 1 && p.first != nil {
		return p.first
	}
	if p.writes == 2 && p.second != nil {
		return p.second
	}
	if p.writes >= 3 && p.retried != nil {
		p.once.Do(func() { close(p.retried) })
	}
	return nil
}

func (*retransmitTestPacketIO) Close() error         { return nil }
func (*retransmitTestPacketIO) LocalAddr() net.Addr  { return nil }
func (*retransmitTestPacketIO) RemoteAddr() net.Addr { return nil }

type blockingPermanentPacketIO struct {
	mu       sync.Mutex
	writes   int
	entered  chan struct{}
	release  chan struct{}
	writeErr error
	once     sync.Once
}

func (p *blockingPermanentPacketIO) ReadPacket(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (p *blockingPermanentPacketIO) WritePacket(context.Context, []byte) error {
	p.mu.Lock()
	p.writes++
	writes := p.writes
	p.mu.Unlock()
	if writes == 2 {
		p.once.Do(func() { close(p.entered) })
		<-p.release
		return p.writeErr
	}
	return nil
}

func (*blockingPermanentPacketIO) Close() error         { return nil }
func (*blockingPermanentPacketIO) LocalAddr() net.Addr  { return nil }
func (*blockingPermanentPacketIO) RemoteAddr() net.Addr { return nil }

func TestRetransmitControlReportsErrorRacingStop(t *testing.T) {
	packetIO := &blockingPermanentPacketIO{
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
		writeErr: errors.New("permanent write at stop"),
	}
	client, err := NewClient(&ClientConfig{}, packetIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.control.Send(context.Background(), PControlV1, []byte("pending")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	stop := client.retransmitControl(ctx, cancel)
	select {
	case <-packetIO.entered:
	case <-time.After(2 * ControlRetransmitDelay):
		t.Fatal("retransmission did not enter blocked write")
	}
	stopped := make(chan struct{})
	go func() {
		stop()
		close(stopped)
	}()
	close(packetIO.release)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("retransmitter did not stop")
	}
	if cause := context.Cause(ctx); cause == nil || !strings.Contains(cause.Error(), "permanent write at stop") {
		t.Fatalf("stop-boundary error was lost: %v", cause)
	}
}

func TestRetransmitControlSuppressesTemporaryErrorRacingStop(t *testing.T) {
	packetIO := &blockingPermanentPacketIO{
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
		writeErr: temporaryControlWriteError{},
	}
	client, err := NewClient(&ClientConfig{}, packetIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.control.Send(context.Background(), PControlV1, []byte("pending")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	stop := client.retransmitControl(ctx, cancel)
	select {
	case <-packetIO.entered:
	case <-time.After(2 * ControlRetransmitDelay):
		t.Fatal("retransmission did not enter blocked write")
	}
	stopped := make(chan struct{})
	go func() {
		stop()
		close(stopped)
	}()
	close(packetIO.release)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("retransmitter did not stop")
	}
	if cause := context.Cause(ctx); cause != nil {
		t.Fatalf("temporary stop-boundary error became operation failure: %v", cause)
	}
}

func TestTemporaryInitialReliableWriteRemainsQueued(t *testing.T) {
	packetIO := &retransmitTestPacketIO{first: temporaryControlWriteError{}}
	client, err := NewClient(&ClientConfig{Proto: ProtoUDP}, packetIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.control.SendReset(context.Background()); err != nil {
		t.Fatalf("temporary initial send failed: %v", err)
	}
	if client.control.PendingMessages() != 1 {
		t.Fatalf("temporary initial send pending = %d, want 1", client.control.PendingMessages())
	}
	if err := client.control.RetransmitPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	packetIO.mu.Lock()
	writes := packetIO.writes
	packetIO.mu.Unlock()
	if writes != 2 {
		t.Fatalf("physical writes = %d, want initial plus retransmit", writes)
	}
}

func TestRetransmitControlRetriesTemporaryError(t *testing.T) {
	packetIO := &retransmitTestPacketIO{second: temporaryControlWriteError{}, retried: make(chan struct{})}
	client, err := NewClient(&ClientConfig{}, packetIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.control.Send(context.Background(), PControlV1, []byte("pending")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	stop := client.retransmitControl(ctx, cancel)
	defer stop()
	select {
	case <-packetIO.retried:
	case <-time.After(3 * ControlRetransmitDelay):
		t.Fatal("temporary retransmission error stopped retry loop")
	}
	if context.Cause(ctx) != nil {
		t.Fatalf("temporary retransmission canceled operation: %v", context.Cause(ctx))
	}
}

func TestRetransmitControlPropagatesPermanentError(t *testing.T) {
	packetIO := &retransmitTestPacketIO{second: errors.New("permanent control write")}
	client, err := NewClient(&ClientConfig{}, packetIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.control.Send(context.Background(), PControlV1, []byte("pending")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	stop := client.retransmitControl(ctx, cancel)
	defer stop()
	select {
	case <-ctx.Done():
		if cause := context.Cause(ctx); cause == nil || !strings.Contains(cause.Error(), "permanent control write") {
			t.Fatalf("unexpected retransmission cause: %v", cause)
		}
	case <-time.After(2 * ControlRetransmitDelay):
		t.Fatal("permanent retransmission error was not propagated")
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
	// lastDeadline records the most recent read deadline. lastWriteDeadline
	// tracks the write side changed by SetDeadline; operationDeadlines retains
	// each two-sided update so tests can verify later AUTH_PENDING replacement.
	lastDeadline       time.Time
	lastWriteDeadline  time.Time
	operationDeadlines []time.Time
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

func (c *chunkConn) SetDeadline(t time.Time) error {
	c.lastDeadline = t
	c.lastWriteDeadline = t
	c.operationDeadlines = append(c.operationDeadlines, t)
	return nil
}

func (c *chunkConn) SetReadDeadline(t time.Time) error {
	c.lastDeadline = t
	return nil
}

func TestReadTokenPushReplyUsesExtendedContinuationDeadline(t *testing.T) {
	limit := time.Now().Add(time.Hour)
	conn := &chunkConn{data: [][]byte{
		[]byte("PUSH_REPLY,push-continuation 2\x00"),
		[]byte("PUSH_REPLY,auth-token SESS_ID_final,push-continuation 1\x00"),
	}}
	reply, rest, err := readTokenPushReply(conn, nil, time.Time{}, time.Time{}, limit)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 || reply == nil || reply.PushContinuation != 1 {
		t.Fatalf("continued reply = %+v rest=%q", reply, rest)
	}
	if conn.lastWriteDeadline != limit || len(conn.operationDeadlines) == 0 || conn.operationDeadlines[0] != limit {
		t.Fatalf("continuation deadline = write %v operations %v, want %v", conn.lastWriteDeadline, conn.operationDeadlines, limit)
	}
	if !conn.lastDeadline.IsZero() {
		t.Fatalf("temporary read deadline was not cleared: %v", conn.lastDeadline)
	}
}

// TestReadTokenPushReplySplitAcrossReads verifies that a token-only PUSH_REPLY
// split across two reads is parsed (TLS is a byte stream).
// TestTakePushReplyAuthPendingBeforePush verifies the exact deferred-auth
// stream from the review: AUTH_PENDING\0INFO_PRE,...\0PUSH_REPLY,...\0.
// The token must be found even though PUSH_REPLY is not the first message.
func TestTakePushReplyAuthPendingBeforePush(t *testing.T) {
	stream := []byte("AUTH_PENDING,timeout 60\x00" +
		"INFO_PRE,Auth-Message:OTAwODcxMjU5MTQ1MDExNjA3MjM=\x00" +
		"PUSH_REPLY,auth-token SESS_ID_fresh\x00")
	reply, rest, ok := takePushReply(stream)
	if !ok {
		t.Fatal("token PUSH_REPLY not found after AUTH_PENDING/INFO_PRE")
	}
	if reply == nil || reply.AuthTokenPass != "SESS_ID_fresh" {
		t.Fatalf("token not parsed: %#v", reply)
	}
	if len(rest) != 0 {
		t.Fatalf("unexpected leftover: %q", rest)
	}
}

// TestReadTokenPushReplyDeferredAuth verifies the full reviewer scenario at
// the readTokenPushReply level: AUTH_PENDING then token PUSH_REPLY in one
// TLS read must yield the token.
func TestReadTokenPushReplyDeferredAuth(t *testing.T) {
	conn := &chunkConn{data: [][]byte{
		[]byte("AUTH_PENDING,timeout 60\x00PUSH_REPLY,auth-token SESS_ID_deferred\x00"),
	}}
	reply, _, err := readTokenPushReply(conn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reply == nil || reply.AuthTokenPass != "SESS_ID_deferred" {
		t.Fatalf("deferred-auth token not parsed: %#v", reply)
	}
}

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

func TestReadServerKeyMethodCompleteWithEOF(t *testing.T) {
	var record []byte
	record = binary.BigEndian.AppendUint32(record, 0)
	record = append(record, KeyMethod2)
	record = append(record, bytes.Repeat([]byte{1}, keySourceRandomSize)...)
	record = append(record, bytes.Repeat([]byte{2}, keySourceRandomSize)...)
	record = appendOpenVPNString(record, "server-options")
	record = appendOpenVPNString(record, "")
	record = appendOpenVPNString(record, "")
	record = appendOpenVPNString(record, "IV_VER=server\n")
	conn := &chunkConn{data: [][]byte{record}, errs: []error{io.EOF}}
	client := &Client{control: &ControlChannel{}}
	parsed, err := client.readServerKeyMethodFrom(context.Background(), conn)
	if err != nil {
		t.Fatalf("complete KM2 with EOF should be accepted: %v", err)
	}
	if parsed.Options != "server-options" || parsed.PeerInfo != "IV_VER=server\n" {
		t.Fatalf("unexpected KM2: %#v", parsed)
	}
}

func TestReadPushReplyEOFBoundaries(t *testing.T) {
	client := &Client{control: &ControlChannel{}}
	complete := &chunkConn{
		data: [][]byte{[]byte("PUSH_REPLY,peer-id 7\x00")},
		errs: []error{io.EOF},
	}
	reply, err := client.readPushReplyFrom(context.Background(), complete)
	if err != nil {
		t.Fatalf("complete PUSH_REPLY with EOF should be accepted: %v", err)
	}
	if reply.PeerID != 7 {
		t.Fatalf("peer id = %d, want 7", reply.PeerID)
	}

	client.leftoverTLS = nil
	incomplete := &chunkConn{
		data: [][]byte{[]byte("PUSH_REPLY,peer-id 7")},
		errs: []error{io.EOF},
	}
	if _, err := client.readPushReplyFrom(context.Background(), incomplete); err == nil {
		t.Fatal("unterminated PUSH_REPLY was accepted at EOF")
	}
}

func TestControlMessageErrorDoesNotLeakAuthToken(t *testing.T) {
	buf := []byte("PUSH_REPLY,auth-token SECRET_TOKEN\x00AUTH_FAILED,SESSION: expired\x00")
	err := controlMessageError(buf)
	if !errors.Is(err, errAuthFailed) {
		t.Fatalf("expected AUTH_FAILED, got %v", err)
	}
	if strings.Contains(err.Error(), "SECRET_TOKEN") {
		t.Fatalf("authentication token leaked in error: %v", err)
	}
	if !strings.Contains(err.Error(), "AUTH_FAILED,SESSION: expired") {
		t.Fatalf("wrong failure message selected: %v", err)
	}
}

func TestTerminalControlMessagesStopTokenRead(t *testing.T) {
	for _, directive := range []string{"RESTART,reconnect", "HALT,disabled", "EXIT"} {
		t.Run(directive, func(t *testing.T) {
			reply, _, err := readTokenPushReply(nil, []byte(directive+"\x00PUSH_REPLY,auth-token SECRET\x00"))
			if !errors.Is(err, errControlTerminated) {
				t.Fatalf("terminal directive was ignored: reply=%#v err=%v", reply, err)
			}
		})
	}
}

func TestMergePushReplyPreservesSplitAuthTokenUser(t *testing.T) {
	first := &PushReply{PeerID: PeerIDUnset, AuthTokenUser: "token-user", PushContinuation: 2, HasPushReply: true}
	final := &PushReply{PeerID: PeerIDUnset, AuthTokenPass: "SESS_ID_new", PushContinuation: 1, HasPushReply: true}
	merged := mergePushReply(first, final)
	if merged.AuthTokenUser != "token-user" || merged.AuthTokenPass != "SESS_ID_new" {
		t.Fatalf("split auth token pair lost: %#v", merged)
	}
}

func TestAuthPendingTimeoutZeroAndCap(t *testing.T) {
	zero, err := parseAuthPendingTimeout("AUTH_PENDING,timeout 0")
	if err != nil {
		t.Fatal(err)
	}
	if !zero.hasAuthPending || zero.AuthPendingTimeout != 0 {
		t.Fatalf("explicit zero timeout lost: %#v", zero)
	}
	establishedAt := time.Now().Add(-time.Second)
	anchorAuthPendingDeadline(zero, establishedAt)
	if !zero.authPendingUntil.Equal(establishedAt) {
		t.Fatalf("zero timeout deadline = %v, want %v", zero.authPendingUntil, establishedAt)
	}
	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.controlEstablishedAt = establishedAt
	client.applyAuthPendingTimeout(zero)
	client.dataLock.RLock()
	stagedSet := client.pendingDeferredSet
	stagedUntil := client.pendingDeferredUntil
	client.dataLock.RUnlock()
	if !stagedSet || !stagedUntil.Equal(establishedAt) {
		t.Fatalf("zero timeout was not applied to pending epoch: set=%v until=%v want=%v", stagedSet, stagedUntil, establishedAt)
	}

	for _, input := range []string{"AUTH_PENDING,timeout 7200", "AUTH_PENDING,timeout 9223372036854775807"} {
		capped, err := parseAuthPendingTimeout(input)
		if err != nil {
			t.Fatal(err)
		}
		if capped.AuthPendingTimeout != authPendingMaxTimeout {
			t.Fatalf("timeout %q was not capped: got=%v want=%v", input, capped.AuthPendingTimeout, authPendingMaxTimeout)
		}
	}
}

func TestTLSControlBufferLimit(t *testing.T) {
	if _, _, err := readTokenPushReply(nil, make([]byte, maxTLSControlBuffer+1)); err == nil {
		t.Fatal("oversized TLS control buffer was accepted")
	}
}
func TestExpiredPendingRetiringWindowPausesUntilInstall(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{Username: "u", Password: "p"}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	mk := func(keyID uint8) *DataChannel {
		keys := &KeyMaterial{
			SendCipherKey: bytes.Repeat([]byte{0x11}, 16),
			SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
			RecvCipherKey: bytes.Repeat([]byte{0x11}, 16),
			RecvHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		}
		data, err := NewDataChannel(keys, CipherAES128GCM, AuthSHA256, 7, keyID)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	initial := mk(0)
	client.installDataChannel(initial)
	client.stageRetiringWindow(time.Now().Add(-time.Second))

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- client.writeDataPacket(context.Background(), []byte{0x45, 0, 0, 20}, false)
	}()
	select {
	case err := <-writeDone:
		t.Fatalf("expired old-key write did not pause: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	// The same old epoch must not accept inbound packets after the deadline.
	peer := mk(0)
	packet, err := peer.Encrypt([]byte{0x45, 0, 0, 20})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.decryptDataPacket(packet); err == nil {
		t.Fatal("old inbound epoch accepted after pending retiring deadline")
	}

	client.installDataChannel(mk(1))
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("new epoch install did not wake paused write")
	}
	emitted, err := serverIO.ReadPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, keyID := parseOpcodeKeyID(emitted[0]); keyID != 1 {
		t.Fatalf("resumed write used key id %d, want 1", keyID)
	}
}

func TestRetiringExpiryStagedBetweenSelectionAndEncryption(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{Username: "u", Password: "p"}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	mk := func(keyID uint8) *DataChannel {
		keys := &KeyMaterial{
			SendCipherKey: bytes.Repeat([]byte{0x11}, 16),
			SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
			RecvCipherKey: bytes.Repeat([]byte{0x11}, 16),
			RecvHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		}
		data, err := NewDataChannel(keys, CipherAES128GCM, AuthSHA256, 7, keyID)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	key0, key1 := mk(0), mk(1)
	client.installDataChannel(key0)
	client.installDataChannel(key1)

	// Block selection in key1.PeerActive while it holds dataLock.RLock.
	key1.mu.Lock()
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- client.writeDataPacket(context.Background(), []byte{0x45, 0, 0, 20}, false)
	}()
	deadline := time.Now().Add(time.Second)
	for client.dataLock.TryLock() {
		client.dataLock.Unlock()
		if time.Now().After(deadline) {
			key1.mu.Unlock()
			t.Fatal("writer did not enter epoch selection")
		}
		time.Sleep(time.Millisecond)
	}
	stageDone := make(chan struct{})
	go func() {
		client.stageRetiringWindow(time.Now().Add(-time.Second))
		close(stageDone)
	}()
	deadline = time.Now().Add(time.Second)
	for client.dataLock.TryRLock() {
		client.dataLock.RUnlock()
		if time.Now().After(deadline) {
			key1.mu.Unlock()
			t.Fatal("retiring deadline writer did not queue")
		}
		time.Sleep(time.Millisecond)
	}
	key1.mu.Unlock()
	select {
	case <-stageDone:
	case <-time.After(time.Second):
		t.Fatal("retiring deadline was not staged")
	}
	select {
	case err := <-writeDone:
		t.Fatalf("write escaped newly staged expired deadline: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	client.installDataChannel(mk(2))
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("writer did not resume on new epoch")
	}
	packet, err := serverIO.ReadPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, keyID := parseOpcodeKeyID(packet[0]); keyID != 2 {
		t.Fatalf("raced write used key id %d, want 2", keyID)
	}
}

func TestRetiringExpiryChangesBetweenSelectionAndEncryption(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{Username: "u", Password: "p"}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	mk := func(keyID uint8) *DataChannel {
		keys := &KeyMaterial{
			SendCipherKey: bytes.Repeat([]byte{0x11}, 16),
			SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
			RecvCipherKey: bytes.Repeat([]byte{0x11}, 16),
			RecvHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		}
		data, err := NewDataChannel(keys, CipherAES128GCM, AuthSHA256, 7, keyID)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	key0, key1 := mk(0), mk(1)
	client.installDataChannel(key0)
	client.installDataChannel(key1)
	key1.mu.Lock()
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- client.writeDataPacket(context.Background(), []byte{0x45, 0, 0, 20}, false)
	}()
	deadline := time.Now().Add(time.Second)
	for client.dataLock.TryLock() {
		client.dataLock.Unlock()
		if time.Now().After(deadline) {
			key1.mu.Unlock()
			t.Fatal("writer did not enter epoch selection")
		}
		time.Sleep(time.Millisecond)
	}
	expiryDone := make(chan struct{})
	go func() {
		client.dataLock.Lock()
		client.retiringExpiry = time.Now().Add(-time.Second)
		client.dataLock.Unlock()
		close(expiryDone)
	}()
	deadline = time.Now().Add(time.Second)
	for client.dataLock.TryRLock() {
		client.dataLock.RUnlock()
		if time.Now().After(deadline) {
			key1.mu.Unlock()
			t.Fatal("retiring expiry writer did not queue")
		}
		time.Sleep(time.Millisecond)
	}
	key1.mu.Unlock()
	select {
	case <-expiryDone:
	case <-time.After(time.Second):
		t.Fatal("retiring expiry was not updated")
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("writer did not finish after promotion")
	}
	packet, err := serverIO.ReadPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, keyID := parseOpcodeKeyID(packet[0]); keyID != 1 {
		t.Fatalf("raced retiring expiry write used key id %d, want 1", keyID)
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

	// The watcher loop consumes a parked same-epoch P_CONTROL_V1
	// (errParkedTLS) whose TLS payload is an AUTH_FAILED message — a
	// deferred authentication that failed. consumeRekeyPush must surface it
	// as a hard error, not swallow it or wait for the next soft reset.
	var serverID SessionID
	copy(serverID[:], []byte("server01"))
	client.control.SetRemoteSessionID(serverID)
	client.control.AdoptKeyID(1)
	// Simulate an established session with a cached push (so the rekey path
	// is taken) and a deferred-auth failure already buffered in the TLS
	// plaintext stream (arrives as a same-epoch P_CONTROL_V1 payload).
	client.push = &PushReply{PeerID: 1, AuthTokenPass: "SESS_ID_old"}
	client.leftoverTLS = []byte("AUTH_FAILED,SESSION: auth-token expired\x00")
	// Park a same-epoch P_CONTROL_V1 so waitForSoftReset returns errParkedTLS.
	// Its payload is the deferred-auth plaintext, which in production is fed
	// through the TLS layer and lands in leftoverTLS (set above).
	client.control.mu.Lock()
	client.control.recvPending[0] = &ControlPacket{
		Opcode:       PControlV1,
		KeyID:        1,
		MessageID:    0,
		LocalSession: serverID,
		Payload:      []byte("deferred auth status"),
	}
	client.control.mu.Unlock()

	done := make(chan struct{})
	go func() {
		client.watchControl()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchControl did not exit after parked AUTH_FAILED")
	}
	if rekeyErr := client.LastRekeyError(); rekeyErr == nil {
		t.Fatal("watchControl swallowed parked AUTH_FAILED")
	} else if !strings.Contains(rekeyErr.Error(), "auth") {
		t.Fatalf("unexpected rekey error: %v", rekeyErr)
	}
}

func TestWatchControlCloseDoesNotRecordRekeyFailure(t *testing.T) {
	clientIO, _ := newMemoryPacketPair()
	client, err := NewClient(&ClientConfig{}, clientIO)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		client.watchControl()
		close(done)
	}()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchControl did not stop on Close")
	}
	if err := client.LastRekeyError(); err != nil {
		t.Fatalf("normal Close recorded a rekey failure: %v", err)
	}
}

// TestMRUCarriesAckOnSubsequentSends verifies the MRU behavior: an ACK queued
// once rides on this packet and the next (OpenVPN lru_acks), not just once.
// TestRetransmitPendingEmptyDoesNotConsumeAcks verifies that retransmitting
// with no pending packets does not consume queued ACKs (they must survive for
// the next real send).
func TestRetransmitPendingEmptyDoesNotConsumeAcks(t *testing.T) {
	clientIO, _ := newMemoryPacketPair()
	var clientID SessionID
	copy(clientID[:], []byte("client01"))
	var serverID SessionID
	copy(serverID[:], []byte("server01"))
	client := NewControlChannel(clientIO, nil, clientID)
	client.SetRemoteSessionID(serverID)
	client.clock = func() time.Time { return time.Unix(1714567890, 0) }

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	client.QueueAck(42)
	if err := client.RetransmitPending(ctx); err != nil {
		t.Fatal(err)
	}
	// ACK 42 must still be pending (nothing was sent, so it was not consumed).
	if len(client.ackPending) != 1 || client.ackPending[0] != 42 {
		t.Fatalf("ackPending after empty retransmit = %v, want [42]", client.ackPending)
	}
}

// TestDecryptRejectsUnknownKeyID verifies a data packet labeled with an
// unknown key epoch is rejected instead of being decrypted with the current
// key (CBC HMAC excludes the outer header, so wrong-key "authentication" must
// not be accepted).
func TestDecryptRejectsUnknownKeyID(t *testing.T) {
	c := &Client{dataByKey: make(map[uint8]*DataChannel)}
	// No current data channel: any key ID is unknown.
	if _, err := c.decryptDataPacket([]byte{byte(PDataV2 << OpcodeShift)}); err == nil {
		t.Fatal("unknown key id was accepted")
	}
}

// TestDecryptRejectsExpiredRetiringKey verifies a data packet from a
// lame-duck epoch is rejected once the transition window has elapsed.
func TestDecryptRejectsExpiredRetiringKey(t *testing.T) {
	current := &DataChannel{keyID: 2}
	retiring := &DataChannel{keyID: 1}
	c := &Client{
		data:           current,
		retiring:       retiring,
		retiringExpiry: time.Now().Add(-time.Second),
		dataByKey:      map[uint8]*DataChannel{1: retiring, 2: current},
	}
	_, err := c.decryptDataPacket([]byte{byte(PDataV2<<OpcodeShift) | 1})
	if err == nil {
		t.Fatal("expired retiring key was accepted")
	}
}

// TestDecryptAcceptsRetiringKeyBeforeExpiry verifies the lame-duck epoch is
// still accepted within the transition window.
func TestDecryptAcceptsRetiringKeyBeforeExpiry(t *testing.T) {
	current := &DataChannel{keyID: 2}
	retiring := &DataChannel{keyID: 1}
	c := &Client{
		data:           current,
		retiring:       retiring,
		retiringExpiry: time.Now().Add(time.Hour),
		dataByKey:      map[uint8]*DataChannel{1: retiring, 2: current},
	}
	// Decryption will fail on the packet (no keys), but the key routing must
	// NOT reject it as unknown/expired.
	_, err := c.decryptDataPacket([]byte{byte(PDataV2<<OpcodeShift) | 1})
	if err != nil && err.Error() == "openvpn data packet with unknown key id" {
		t.Fatalf("retiring key rejected before expiry: %v", err)
	}
	if err != nil && err.Error() == "openvpn data packet from expired retiring epoch" {
		t.Fatalf("retiring key rejected as expired before expiry: %v", err)
	}
}

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

// TestReadTokenPushReplyClearsDeadlineOnSuccess verifies a successful token
// read clears the temporary 300 ms read deadline (the errParkedTLS path runs
// outside renegotiate's deadline cleanup, so a stale deadline would tear down
// the idle established connection).
func TestReadTokenPushReplyClearsDeadlineOnSuccess(t *testing.T) {
	conn := &chunkConn{
		data: [][]byte{[]byte("PUSH_REPLY,auth-token SESS_ID_new\x00")},
	}
	reply, _, err := readTokenPushReply(conn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reply == nil {
		t.Fatal("expected a reply")
	}
	if !conn.lastDeadline.IsZero() {
		t.Fatalf("read deadline not cleared on success: %v", conn.lastDeadline)
	}
}

// TestReadTokenPushReplyClearsDeadlineOnError verifies the deadline is cleared
// when no reply is obtained (timeout path).
func TestReadTokenPushReplyClearsDeadlineOnError(t *testing.T) {
	conn := &chunkConn{data: [][]byte{}}
	reply, _, err := readTokenPushReply(conn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reply != nil {
		t.Fatalf("unexpected reply: %#v", reply)
	}
	if !conn.lastDeadline.IsZero() {
		t.Fatalf("read deadline not cleared on no-data path: %v", conn.lastDeadline)
	}
}

// TestReadAllEmitsParkedBeforeContiguous verifies out-of-order reliable
// control payloads are fed to TLS in the order they were received: parkedTLS
// (already advanced recvMessage) precedes subsequently contiguous recvPending.
func TestReadAllEmitsParkedBeforeContiguous(t *testing.T) {
	c := &ControlChannel{
		recvPending: map[uint32]*ControlPacket{
			2: {Opcode: PControlV1, MessageID: 2, Payload: []byte("later")},
		},
		recvMessage: 2,
		parkedTLS:   [][]byte{[]byte("earlier")},
	}
	out := c.ReadAll()
	if len(out) != 2 {
		t.Fatalf("len = %d, want 2", len(out))
	}
	if string(out[0].Payload) != "earlier" || string(out[1].Payload) != "later" {
		t.Fatalf("order wrong: %q then %q", out[0].Payload, out[1].Payload)
	}
}

// TestWaitForSoftResetRejectsInvalidParkedReset verifies a parked soft reset
// with a non-zero message ID is dropped on consume, never advancing the
// receive sequence.
func TestWaitForSoftResetRejectsInvalidParkedReset(t *testing.T) {
	client, server := newTestChannels(t)
	client.SetRemoteSessionID(server.LocalSessionID())
	server.SetRemoteSessionID(client.LocalSessionID())
	client.AdoptKeyID(1)
	client.pendingSoftReset = &ControlPacket{
		Opcode:       PControlSoftResetV1,
		KeyID:        2,
		MessageID:    5,
		LocalSession: server.LocalSessionID(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	// The invalid parked reset must not be returned; the wait times out
	// because no valid reset arrives.
	if _, err := client.waitForSoftReset(ctx); err == nil {
		t.Fatal("invalid parked reset was accepted")
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
	// soft reset. The watcher must park the token (and surface it now), not
	// drop it or wait for the next soft reset.
	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = server.Send(ctx, PControlV1, []byte("PUSH_REPLY,auth-token SESS_ID_parked\x00"))
		time.Sleep(20 * time.Millisecond)
		server.AdoptKeyID(2)
		_, _ = server.Send(ctx, PControlSoftResetV1, nil)
	}()

	// First wait surfaces the parked TLS payload so the caller consumes it
	// immediately (a late AUTH_FAILED must not wait for the next soft reset).
	_, err := client.waitForSoftReset(ctx)
	if !errors.Is(err, errParkedTLS) {
		t.Fatalf("expected errParkedTLS, got %v", err)
	}
	queued := client.ReadAll()
	if len(queued) != 1 || string(queued[0].Payload) != "PUSH_REPLY,auth-token SESS_ID_parked\x00" {
		t.Fatalf("parked payload lost: %#v", queued)
	}

	// Then the soft reset is delivered.
	got, err := client.waitForSoftReset(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Opcode != PControlSoftResetV1 || got.KeyID != 2 {
		t.Fatalf("got %s key=%d", got.Opcode, got.KeyID)
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
