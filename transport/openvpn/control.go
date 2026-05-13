package openvpn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type PacketIO interface {
	ReadPacket(ctx context.Context) ([]byte, error)
	WritePacket(ctx context.Context, packet []byte) error
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type ControlChannel struct {
	io     PacketIO
	crypt  *TLSCrypt
	clock  func() time.Time
	keyID  uint8
	local  SessionID
	remote SessionID

	mu            sync.Mutex
	sendPacketID  uint32
	sendMessage   uint32
	ackPending    []uint32
	pending       map[uint32]*ControlPacket
	readDeadline  time.Time
	writeDeadline time.Time
}

func NewControlChannel(io PacketIO, crypt *TLSCrypt, local SessionID) *ControlChannel {
	return &ControlChannel{
		io:      io,
		crypt:   crypt,
		clock:   time.Now,
		local:   local,
		pending: make(map[uint32]*ControlPacket),
	}
}

func (c *ControlChannel) LocalSessionID() SessionID {
	return c.local
}

func (c *ControlChannel) RemoteSessionID() SessionID {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remote
}

func (c *ControlChannel) SetRemoteSessionID(id SessionID) {
	c.mu.Lock()
	c.remote = id
	c.mu.Unlock()
}

func (c *ControlChannel) SendReset(ctx context.Context) error {
	_, err := c.Send(ctx, PControlHardResetClientV2, nil)
	return err
}

func (c *ControlChannel) Send(ctx context.Context, opcode Opcode, payload []byte) (uint32, error) {
	if !opcode.HasMessageID() {
		return 0, fmt.Errorf("opcode %s cannot carry a reliable message", opcode)
	}

	c.mu.Lock()
	messageID := c.sendMessage
	c.sendMessage++
	packet := &ControlPacket{
		Opcode:           opcode,
		KeyID:            c.keyID,
		LocalSession:     c.local,
		AckIDs:           append([]uint32(nil), c.ackPending...),
		AckRemoteSession: c.remote,
		MessageID:        messageID,
		Payload:          cloneBytes(payload),
	}
	c.ackPending = nil
	c.pending[messageID] = packet
	c.mu.Unlock()

	if err := c.writeControlPacket(ctx, packet); err != nil {
		return 0, err
	}
	return messageID, nil
}

func (c *ControlChannel) SendAck(ctx context.Context) error {
	c.mu.Lock()
	if len(c.ackPending) == 0 {
		c.mu.Unlock()
		return nil
	}
	packet := &ControlPacket{
		Opcode:           PAckV1,
		KeyID:            c.keyID,
		LocalSession:     c.local,
		AckIDs:           append([]uint32(nil), c.ackPending...),
		AckRemoteSession: c.remote,
	}
	c.ackPending = nil
	c.mu.Unlock()
	return c.writeControlPacket(ctx, packet)
}

func (c *ControlChannel) Read(ctx context.Context) (*ControlPacket, error) {
	for {
		packet, err := c.readControlPacket(ctx)
		if err != nil {
			return nil, err
		}

		c.mu.Lock()
		if c.remote == (SessionID{}) && packet.LocalSession != c.local {
			c.remote = packet.LocalSession
		}
		for _, ackID := range packet.AckIDs {
			delete(c.pending, ackID)
		}
		if packet.Opcode.HasMessageID() {
			c.ackPending = appendAck(c.ackPending, packet.MessageID)
		}
		c.mu.Unlock()

		if packet.Opcode == PAckV1 {
			continue
		}
		return packet, nil
	}
}

func (c *ControlChannel) PendingMessages() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}

func (c *ControlChannel) RetransmitPending(ctx context.Context) error {
	c.mu.Lock()
	packets := make([]*ControlPacket, 0, len(c.pending))
	for _, packet := range c.pending {
		cp := *packet
		cp.AckIDs = append([]uint32(nil), c.ackPending...)
		cp.AckRemoteSession = c.remote
		packets = append(packets, &cp)
	}
	c.ackPending = nil
	c.mu.Unlock()

	for _, packet := range packets {
		if err := c.writeControlPacket(ctx, packet); err != nil {
			return err
		}
	}
	return nil
}

func (c *ControlChannel) writeControlPacket(ctx context.Context, packet *ControlPacket) error {
	c.mu.Lock()
	c.sendPacketID++
	packetID := c.sendPacketID
	unixTime := uint32(c.clock().Unix())
	deadline := c.writeDeadline
	c.mu.Unlock()

	if !deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}

	encoded, err := packet.Encode(c.crypt, packetID, unixTime)
	if err != nil {
		return err
	}
	return c.io.WritePacket(ctx, encoded)
}

func (c *ControlChannel) readControlPacket(ctx context.Context) (*ControlPacket, error) {
	c.mu.Lock()
	deadline := c.readDeadline
	c.mu.Unlock()

	if !deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}

	raw, err := c.io.ReadPacket(ctx)
	if err != nil {
		return nil, err
	}
	packet, _, _, err := DecodeControlPacket(c.crypt, raw)
	return packet, err
}

func (c *ControlChannel) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *ControlChannel) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *ControlChannel) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

func appendAck(acks []uint32, ack uint32) []uint32 {
	for _, existing := range acks {
		if existing == ack {
			return acks
		}
	}
	return append(acks, ack)
}

type ControlConn struct {
	channel *ControlChannel
	readBuf []byte
	closed  bool
	mu      sync.Mutex
}

func NewControlConn(channel *ControlChannel) *ControlConn {
	return &ControlConn{channel: channel}
}

func (c *ControlConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()

	for {
		packet, err := c.channel.Read(context.Background())
		if err != nil {
			return 0, err
		}
		if packet.Opcode != PControlV1 {
			if err := c.channel.SendAck(context.Background()); err != nil {
				return 0, err
			}
			continue
		}
		if err := c.channel.SendAck(context.Background()); err != nil {
			return 0, err
		}
		if len(packet.Payload) == 0 {
			continue
		}
		n := copy(b, packet.Payload)
		if n < len(packet.Payload) {
			c.mu.Lock()
			c.readBuf = append(c.readBuf, packet.Payload[n:]...)
			c.mu.Unlock()
		}
		return n, nil
	}
}

func (c *ControlConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.mu.Unlock()

	if _, err := c.channel.Send(context.Background(), PControlV1, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *ControlConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	return c.channel.io.Close()
}

func (c *ControlConn) LocalAddr() net.Addr {
	return c.channel.io.LocalAddr()
}

func (c *ControlConn) RemoteAddr() net.Addr {
	return c.channel.io.RemoteAddr()
}

func (c *ControlConn) SetDeadline(t time.Time) error {
	return c.channel.SetDeadline(t)
}

func (c *ControlConn) SetReadDeadline(t time.Time) error {
	return c.channel.SetReadDeadline(t)
}

func (c *ControlConn) SetWriteDeadline(t time.Time) error {
	return c.channel.SetWriteDeadline(t)
}

type streamPacketIO struct {
	conn net.Conn
}

type datagramPacketIO struct {
	conn net.Conn
}

func NewDatagramPacketIO(conn net.Conn) PacketIO {
	return &datagramPacketIO{conn: conn}
}

func (d *datagramPacketIO) ReadPacket(ctx context.Context) ([]byte, error) {
	done := make(chan struct{})
	var (
		packet []byte
		err    error
	)
	go func() {
		defer close(done)
		buf := make([]byte, 64*1024)
		var n int
		n, err = d.conn.Read(buf)
		if err == nil {
			packet = cloneBytes(buf[:n])
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
		return packet, err
	}
}

func (d *datagramPacketIO) WritePacket(ctx context.Context, packet []byte) error {
	done := make(chan error, 1)
	go func() {
		_, err := d.conn.Write(packet)
		done <- err
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func (d *datagramPacketIO) Close() error {
	return d.conn.Close()
}

func (d *datagramPacketIO) LocalAddr() net.Addr {
	return d.conn.LocalAddr()
}

func (d *datagramPacketIO) RemoteAddr() net.Addr {
	return d.conn.RemoteAddr()
}

func NewTCPPacketIO(conn net.Conn) PacketIO {
	return &streamPacketIO{conn: conn}
}

func (s *streamPacketIO) ReadPacket(ctx context.Context) ([]byte, error) {
	done := make(chan struct{})
	var (
		packet []byte
		err    error
	)
	go func() {
		defer close(done)
		var lenBuf [2]byte
		if _, err = io.ReadFull(s.conn, lenBuf[:]); err != nil {
			return
		}
		size := int(lenBuf[0])<<8 | int(lenBuf[1])
		if size == 0 {
			err = errors.New("empty openvpn tcp packet")
			return
		}
		packet = make([]byte, size)
		_, err = io.ReadFull(s.conn, packet)
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
		return packet, err
	}
}

func (s *streamPacketIO) WritePacket(ctx context.Context, packet []byte) error {
	if len(packet) > 0xffff {
		return fmt.Errorf("openvpn tcp packet too large: %d", len(packet))
	}
	done := make(chan error, 1)
	go func() {
		frame := make([]byte, 2+len(packet))
		frame[0] = byte(len(packet) >> 8)
		frame[1] = byte(len(packet))
		copy(frame[2:], packet)
		_, err := s.conn.Write(frame)
		done <- err
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func (s *streamPacketIO) Close() error {
	return s.conn.Close()
}

func (s *streamPacketIO) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *streamPacketIO) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}
