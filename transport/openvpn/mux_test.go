package openvpn

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
)

type readErrorPacketIO struct {
	err    error
	closed chan struct{}
	once   sync.Once
}

func (p *readErrorPacketIO) ReadPacket(context.Context) ([]byte, error) {
	return nil, p.err
}

func (p *readErrorPacketIO) WritePacket(context.Context, []byte) error {
	return nil
}

func (p *readErrorPacketIO) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

func (p *readErrorPacketIO) LocalAddr() net.Addr {
	return dummyAddr("local")
}

func (p *readErrorPacketIO) RemoteAddr() net.Addr {
	return dummyAddr("remote")
}

func TestPacketMuxPreservesReadError(t *testing.T) {
	readErr := errors.New("read connected UDP socket: connection refused")
	packetIO := &readErrorPacketIO{err: readErr, closed: make(chan struct{})}
	mux := NewPacketMux(packetIO)

	go mux.Run(context.Background())
	<-packetIO.closed

	if _, err := mux.ReadPacket(context.Background()); !errors.Is(err, readErr) {
		t.Fatalf("control read error = %v; want %v", err, readErr)
	}
	if _, err := mux.ReadDataPacket(context.Background()); !errors.Is(err, readErr) {
		t.Fatalf("data read error = %v; want %v", err, readErr)
	}
}

func TestPacketMuxExplicitCloseReturnsNetErrClosed(t *testing.T) {
	packetIO := &readErrorPacketIO{err: errors.New("unexpected read"), closed: make(chan struct{})}
	mux := NewPacketMux(packetIO)

	if err := mux.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := mux.ReadDataPacket(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("data read error = %v; want %v", err, net.ErrClosed)
	}
}
