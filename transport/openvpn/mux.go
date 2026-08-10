package openvpn

import (
	"context"
	"net"
	"sync"
)

type PacketMux struct {
	io PacketIO

	control chan []byte
	data    chan []byte
	done    chan struct{}
	once    sync.Once
	errMu   sync.RWMutex
	readErr error
}

func NewPacketMux(io PacketIO) *PacketMux {
	return &PacketMux{
		io:      io,
		control: make(chan []byte, 64),
		data:    make(chan []byte, 256),
		done:    make(chan struct{}),
	}
}

func (m *PacketMux) Run(ctx context.Context) {
	defer m.Close()
	for ctx.Err() == nil {
		packet, err := m.io.ReadPacket(ctx)
		if err != nil {
			if ctx.Err() == nil {
				m.closeWithError(err)
			}
			return
		}
		if len(packet) == 0 {
			continue
		}
		opcode, _ := parseOpcodeKeyID(packet[0])
		ch := m.data
		if opcode.IsControl() {
			ch = m.control
		}
		select {
		case ch <- packet:
		case <-ctx.Done():
			return
		case <-m.done:
			return
		}
	}
}

func (m *PacketMux) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case packet := <-m.control:
		return packet, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.done:
		return nil, m.terminalError()
	}
}

func (m *PacketMux) ReadDataPacket(ctx context.Context) ([]byte, error) {
	select {
	case packet := <-m.data:
		return packet, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.done:
		return nil, m.terminalError()
	}
}

func (m *PacketMux) WritePacket(ctx context.Context, packet []byte) error {
	return m.io.WritePacket(ctx, packet)
}

func (m *PacketMux) Close() error {
	m.closeWithError(net.ErrClosed)
	return nil
}

func (m *PacketMux) closeWithError(err error) {
	m.once.Do(func() {
		m.errMu.Lock()
		m.readErr = err
		m.errMu.Unlock()
		close(m.done)
		_ = m.io.Close()
	})
}

func (m *PacketMux) terminalError() error {
	m.errMu.RLock()
	err := m.readErr
	m.errMu.RUnlock()
	if err == nil {
		return net.ErrClosed
	}
	return err
}

func (m *PacketMux) LocalAddr() net.Addr {
	return m.io.LocalAddr()
}

func (m *PacketMux) RemoteAddr() net.Addr {
	return m.io.RemoteAddr()
}
