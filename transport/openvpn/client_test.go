package openvpn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"
)

type fakeControlStream struct {
	readCh  chan []byte
	writeCh chan []byte

	mu           sync.Mutex
	readDeadline time.Time
	closed       bool
}

func newFakeControlStream() *fakeControlStream {
	return &fakeControlStream{
		readCh:  make(chan []byte, 8),
		writeCh: make(chan []byte, 8),
	}
}

func (f *fakeControlStream) Read(b []byte) (int, error) {
	f.mu.Lock()
	deadline := f.readDeadline
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if deadline.IsZero() {
		msg, ok := <-f.readCh
		if !ok {
			return 0, net.ErrClosed
		}
		return copy(b, msg), nil
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case msg, ok := <-f.readCh:
		if !ok {
			return 0, net.ErrClosed
		}
		return copy(b, msg), nil
	case <-timer.C:
		return 0, timeoutError{}
	}
}

func (f *fakeControlStream) Write(b []byte) (int, error) {
	f.mu.Lock()
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	f.writeCh <- cloneBytes(b)
	return len(b), nil
}

func (f *fakeControlStream) SetReadDeadline(t time.Time) error {
	f.mu.Lock()
	f.readDeadline = t
	f.mu.Unlock()
	return nil
}

func (f *fakeControlStream) SetWriteDeadline(time.Time) error {
	return nil
}

func (f *fakeControlStream) Close() {
	f.mu.Lock()
	if !f.closed {
		f.closed = true
		close(f.readCh)
	}
	f.mu.Unlock()
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type oneShotReadErrorStream struct {
	*fakeControlStream

	mu  sync.Mutex
	err error
}

func newOneShotReadErrorStream(err error) *oneShotReadErrorStream {
	return &oneShotReadErrorStream{
		fakeControlStream: newFakeControlStream(),
		err:               err,
	}
}

func (s *oneShotReadErrorStream) Read(b []byte) (int, error) {
	s.mu.Lock()
	err := s.err
	s.err = nil
	s.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return s.fakeControlStream.Read(b)
}

func TestClientInstallDataChannelRekeysWithoutReplacingDataChannel(t *testing.T) {
	client := &Client{
		config: &ClientConfig{
			Cipher: CipherAES128GCM,
			Auth:   AuthSHA256,
		},
		activity: newRemoteActivity(),
	}
	keys1 := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x11}, 16),
		SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x33}, 16),
		RecvHMACKey:   bytes.Repeat([]byte{0x44}, maxHMACKeyLength),
	}
	keys2 := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x55}, 16),
		SendHMACKey:   bytes.Repeat([]byte{0x66}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x77}, 16),
		RecvHMACKey:   bytes.Repeat([]byte{0x88}, maxHMACKeyLength),
	}
	if err := client.installDataChannel(keys1, &PushReply{PeerID: 7}, false); err != nil {
		t.Fatal(err)
	}
	initial := client.data
	if initial == nil {
		t.Fatal("expected initial data channel")
	}
	if err := client.installDataChannel(keys2, &PushReply{PeerID: 7}, true); err != nil {
		t.Fatal(err)
	}
	if client.data != initial {
		t.Fatal("expected in-place rekey to keep the data channel object")
	}
	encrypted, err := client.data.Encrypt([]byte{0x45, 0, 0, 20, 1, 2, 3, 4, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, keyID := parseOpcodeKeyID(encrypted[0]); keyID != 1 {
		t.Fatalf("expected encrypted packets to use rekeyed key id 1, got %d", keyID)
	}
}

func TestClientInstallDataChannelRetiresPreviousReceiveKeyAfterOverlap(t *testing.T) {
	clientKeys1 := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x11}, 16),
		SendHMACKey:   bytes.Repeat([]byte{0x22}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x33}, 16),
		RecvHMACKey:   bytes.Repeat([]byte{0x44}, maxHMACKeyLength),
	}
	serverKeys1 := &KeyMaterial{
		SendCipherKey: clientKeys1.RecvCipherKey,
		SendHMACKey:   clientKeys1.RecvHMACKey,
		RecvCipherKey: clientKeys1.SendCipherKey,
		RecvHMACKey:   clientKeys1.SendHMACKey,
	}
	clientKeys2 := &KeyMaterial{
		SendCipherKey: bytes.Repeat([]byte{0x55}, 16),
		SendHMACKey:   bytes.Repeat([]byte{0x66}, maxHMACKeyLength),
		RecvCipherKey: bytes.Repeat([]byte{0x77}, 16),
		RecvHMACKey:   bytes.Repeat([]byte{0x88}, maxHMACKeyLength),
	}
	serverKeys2 := &KeyMaterial{
		SendCipherKey: clientKeys2.RecvCipherKey,
		SendHMACKey:   clientKeys2.RecvHMACKey,
		RecvCipherKey: clientKeys2.SendCipherKey,
		RecvHMACKey:   clientKeys2.SendHMACKey,
	}
	client := &Client{
		config: &ClientConfig{
			Cipher: CipherAES128GCM,
			Auth:   AuthSHA256,
		},
		activity: newRemoteActivity(),
	}
	if err := client.installDataChannel(clientKeys1, &PushReply{PeerID: 7}, false); err != nil {
		t.Fatal(err)
	}
	server, err := NewDataChannel(serverKeys1, CipherAES128GCM, AuthSHA256, 7)
	if err != nil {
		t.Fatal(err)
	}
	oldPacketDuringOverlap := []byte{0x45, 0, 0, 20, 1, 2, 3, 4, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1}
	oldEncryptedDuringOverlap, err := server.Encrypt(oldPacketDuringOverlap)
	if err != nil {
		t.Fatal(err)
	}
	oldPacketAfterOverlap := []byte{0x45, 0, 0, 20, 1, 2, 3, 6, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1}
	oldEncryptedAfterOverlap, err := server.Encrypt(oldPacketAfterOverlap)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.installDataChannel(clientKeys2, &PushReply{PeerID: 7}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := client.data.Decrypt(oldEncryptedDuringOverlap); err != nil {
		t.Fatalf("expected old receive key to remain during overlap: %v", err)
	}
	if err := server.Rekey(serverKeys2, CipherAES128GCM, AuthSHA256, 7); err != nil {
		t.Fatal(err)
	}
	newPacket := []byte{0x45, 0, 0, 20, 1, 2, 3, 5, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1}
	newEncrypted, err := server.Encrypt(newPacket)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(dataChannelRekeyOverlap + 100*time.Millisecond)

	if _, err := client.data.Decrypt(oldEncryptedAfterOverlap); err == nil {
		t.Fatal("expected old receive key to be retired after overlap")
	}
	if _, err := client.data.Decrypt(newEncrypted); err != nil {
		t.Fatalf("expected active receive key to remain after overlap: %v", err)
	}
}

func TestClientConsumePushReplyFramesWaitsForNULTerminator(t *testing.T) {
	client := &Client{config: &ClientConfig{RemoteHost: "test", RemotePort: 1194}}
	var options []string
	fragments := 0
	buf := []byte("PUSH_REPLY,ifconfig 198.51.100.2")

	if reply, done, err := client.consumePushReplyFrames(&buf, &options, &fragments); err != nil || done || reply != nil {
		t.Fatalf("expected incomplete frame to be ignored, reply=%v done=%v err=%v", reply, done, err)
	}
	if got := string(buf); got != "PUSH_REPLY,ifconfig 198.51.100.2" {
		t.Fatalf("expected incomplete bytes to remain buffered, got %q", got)
	}

	buf = append(buf, []byte(" 255.255.255.0,peer-id 7\x00")...)
	reply, done, err := client.consumePushReplyFrames(&buf, &options, &fragments)
	if err != nil {
		t.Fatal(err)
	}
	if !done || reply == nil {
		t.Fatalf("expected complete push reply, done=%v reply=%v", done, reply)
	}
	if reply.PeerID != 7 {
		t.Fatalf("unexpected peer-id: %d", reply.PeerID)
	}
	if len(buf) != 0 {
		t.Fatalf("expected buffer to be consumed, got %q", string(buf))
	}
}

func TestClientConsumePushReplyFramesHandlesMultipleFramesInOneRead(t *testing.T) {
	client := &Client{config: &ClientConfig{RemoteHost: "test", RemotePort: 1194}}
	var options []string
	fragments := 0
	buf := []byte("AUTH_PENDING,timeout 1\x00PUSH_REPLY,ifconfig 198.51.100.2 255.255.255.0,peer-id 7\x00")

	reply, done, err := client.consumePushReplyFrames(&buf, &options, &fragments)
	if err != nil {
		t.Fatal(err)
	}
	if !done || reply == nil {
		t.Fatalf("expected complete push reply after auth-pending frame, done=%v reply=%v", done, reply)
	}
	if reply.PeerID != 7 {
		t.Fatalf("unexpected peer-id: %d", reply.PeerID)
	}
}

func TestClientConsumePushReplyFramesLimitsContinuationFragments(t *testing.T) {
	client := &Client{config: &ClientConfig{RemoteHost: "test", RemotePort: 1194}}
	var options []string
	fragments := 0
	var buf []byte
	for i := 0; i < maxPushReplyFragments+1; i++ {
		buf = append(buf, []byte("PUSH_REPLY,route 198.51.100.0 255.255.255.0,push-continuation 2\x00")...)
	}

	_, _, err := client.consumePushReplyFrames(&buf, &options, &fragments)
	if err == nil {
		t.Fatal("expected continuation fragment limit error")
	}
}

func TestClientCompLZOFramingIsAppliedOnce(t *testing.T) {
	clientIO, serverIO := newMemoryPacketPair()
	clientMux := NewPacketMux(clientIO)
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go clientMux.Run(runCtx)

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
	client := &Client{
		config: &ClientConfig{
			Cipher:  CipherAES128GCM,
			Auth:    AuthSHA256,
			CompLZO: CompLzoYes,
		},
		mux:      clientMux,
		writeSem: *semaphore.NewWeighted(1),
	}
	if err := client.installDataChannel(clientKeys, &PushReply{PeerID: 7}, false); err != nil {
		t.Fatal(err)
	}
	server, err := NewDataChannel(serverKeys, CipherAES128GCM, AuthSHA256, 7)
	if err != nil {
		t.Fatal(err)
	}

	packet := []byte{0x45, 0, 0, 20, 1, 2, 3, 4, 64, 6, 0, 0, 10, 8, 0, 2, 1, 1, 1, 1}
	if err := client.WriteIPPacket(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	raw, err := serverIO.ReadPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	plain, err := server.Decrypt(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := lzo1xDecompressSafe(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, packet) {
		t.Fatalf("expected one comp-lzo frame, got %x want %x", got, packet)
	}
}

func TestRunControlLoopSendsPing(t *testing.T) {
	stream := newFakeControlStream()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runControlLoop(ctx, stream, &PushReply{
			PingInterval: 20 * time.Millisecond,
			PingRestart:  200 * time.Millisecond,
		}, "test", newRemoteActivity())
	}()

	select {
	case msg := <-stream.writeCh:
		if got := string(msg); got != "PING\x00" {
			t.Fatalf("unexpected ping payload: %q", got)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("control loop did not send PING")
	}

	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestRunControlLoopRestartsOnPingTimeout(t *testing.T) {
	stream := newFakeControlStream()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := runControlLoop(ctx, stream, &PushReply{PingRestart: 30 * time.Millisecond}, "test", newRemoteActivity())
	if !errors.Is(err, ErrControlRestart) {
		t.Fatalf("expected restart on ping timeout, got %v", err)
	}
	if !strings.Contains(err.Error(), "ping-restart") {
		t.Fatalf("expected ping-restart reason, got %v", err)
	}
}

func TestRunControlLoopRekeysOnRenegSec(t *testing.T) {
	stream := newFakeControlStream()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rekeys := 0
	err := runControlLoopWithHooks(ctx, stream, &PushReply{RenegotiateAfter: time.Millisecond}, "test", newRemoteActivity(), controlLoopHooks{
		rekey: func(context.Context, string) (*PushReply, controlStream, error) {
			rekeys++
			cancel()
			return &PushReply{RenegotiateAfter: time.Hour}, stream, nil
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation after successful rekey, got %v", err)
	}
	if rekeys != 1 {
		t.Fatalf("expected one in-place rekey, got %d", rekeys)
	}
}

func TestRunControlLoopFallsBackWhenRekeyFails(t *testing.T) {
	stream := newFakeControlStream()
	err := runControlLoopWithHooks(context.Background(), stream, &PushReply{RenegotiateAfter: time.Millisecond}, "test", newRemoteActivity(), controlLoopHooks{
		rekey: func(context.Context, string) (*PushReply, controlStream, error) {
			return nil, nil, errors.New("boom")
		},
	})
	if !errors.Is(err, ErrControlRestart) {
		t.Fatalf("expected reconnect fallback, got %v", err)
	}
	if !strings.Contains(err.Error(), "rekey failed") {
		t.Fatalf("expected rekey failure reason, got %v", err)
	}
}

func TestRunControlLoopRekeysOnServerSoftRestartMessage(t *testing.T) {
	stream := newFakeControlStream()
	stream.readCh <- []byte("RESTART,soft\x00")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rekeys := 0
	err := runControlLoopWithHooks(ctx, stream, &PushReply{}, "test", newRemoteActivity(), controlLoopHooks{
		rekey: func(context.Context, string) (*PushReply, controlStream, error) {
			rekeys++
			cancel()
			return &PushReply{RenegotiateAfter: time.Hour}, stream, nil
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation after successful soft restart rekey, got %v", err)
	}
	if rekeys != 1 {
		t.Fatalf("expected one in-place rekey, got %d", rekeys)
	}
}

func TestRunControlLoopRekeysOnServerSoftResetPacket(t *testing.T) {
	stream := newOneShotReadErrorStream(fmt.Errorf("%w: %w: received P_CONTROL_SOFT_RESET_V1", ErrControlRestart, ErrControlSoftReset))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	rekeys := 0
	err := runControlLoopWithHooks(ctx, stream, &PushReply{}, "test", newRemoteActivity(), controlLoopHooks{
		rekey: func(context.Context, string) (*PushReply, controlStream, error) {
			rekeys++
			cancel()
			return &PushReply{RenegotiateAfter: time.Hour}, stream, nil
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation after successful soft reset rekey, got %v", err)
	}
	if rekeys != 1 {
		t.Fatalf("expected one in-place rekey, got %d", rekeys)
	}
}

func TestRunControlLoopRestartsOnServerHardRestartMessage(t *testing.T) {
	stream := newFakeControlStream()
	stream.readCh <- []byte("HALT,server-exit\x00")

	err := runControlLoop(context.Background(), stream, &PushReply{}, "test", newRemoteActivity())
	if !errors.Is(err, ErrControlRestart) {
		t.Fatalf("expected restart on server HALT, got %v", err)
	}
}

func TestRunControlLoopReturnsAuthFailure(t *testing.T) {
	stream := newFakeControlStream()
	stream.readCh <- []byte("AUTH_FAILED,denied\x00")

	err := runControlLoop(context.Background(), stream, &PushReply{}, "test", newRemoteActivity())
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("expected auth failure, got %v", err)
	}
}

func TestRunControlLoopDataActivityPreventsPingRestart(t *testing.T) {
	stream := newFakeControlStream()
	activity := newRemoteActivity()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runControlLoop(ctx, stream, &PushReply{PingRestart: 60 * time.Millisecond}, "test", activity)
	}()

	time.Sleep(40 * time.Millisecond)
	activity.Mark()

	select {
	case err := <-errCh:
		t.Fatalf("control loop stopped despite data-channel activity: %v", err)
	case <-time.After(40 * time.Millisecond):
	}

	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}
