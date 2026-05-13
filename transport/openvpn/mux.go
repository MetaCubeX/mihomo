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
		return nil, net.ErrClosed
	}
}

func (m *PacketMux) ReadDataPacket(ctx context.Context) ([]byte, error) {
	select {
	case packet := <-m.data:
		return packet, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.done:
		return nil, net.ErrClosed
	}
}

func (m *PacketMux) WritePacket(ctx context.Context, packet []byte) error {
	return m.io.WritePacket(ctx, packet)
}

func (m *PacketMux) Close() error {
	m.once.Do(func() {
		close(m.done)
		_ = m.io.Close()
	})
	return nil
}

func (m *PacketMux) LocalAddr() net.Addr {
	return m.io.LocalAddr()
}

func (m *PacketMux) RemoteAddr() net.Addr {
	return m.io.RemoteAddr()
}
