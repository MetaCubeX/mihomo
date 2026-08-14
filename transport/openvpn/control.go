package openvpn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/pool"
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
	crypt  ControlCryptor
	clock  func() time.Time
	keyID  uint8
	local  SessionID
	remote SessionID

	mu            sync.Mutex
	sendPacketID  uint32
	sendMessage   uint32
	recvMessage   uint32
	ackPending    []uint32
	// lruAcks is the MRU of recently acknowledged packet IDs, mirroring
	// OpenVPN's reliable_ack.lru_acks: acks are copied here when sent and
	// kept so subsequent control packets repeat them until replaced.
	lruAcks        []uint32
	pending        map[uint32]*ControlPacket
	recvPending    map[uint32]*ControlPacket
	// pendingSoftReset holds a server soft-reset that arrived while the
	// current epoch was still doing TLS/key-method. waitForSoftReset
	// consumes it so ControlConn.Read cannot swallow it.
	pendingSoftReset *ControlPacket
	// parkedTLS holds same-epoch P_CONTROL_V1 payloads that arrived while
	// the watcher was waiting for a soft reset (typically a token-only
	// PUSH_REPLY). ReadAll drains them into leftoverTLS / tls.Conn.
	parkedTLS    [][]byte
	readDeadline time.Time
	writeDeadline time.Time
}

func NewControlChannel(io PacketIO, crypt ControlCryptor, local SessionID) *ControlChannel {
	return &ControlChannel{
		io:          io,
		crypt:       crypt,
		clock:       time.Now,
		local:       local,
		pending:     make(map[uint32]*ControlPacket),
		recvPending: make(map[uint32]*ControlPacket),
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
	opcode := PControlHardResetClientV2
	if _, isTLSCryptV2 := c.crypt.(*TLSCryptV2); isTLSCryptV2 {
		opcode = PControlHardResetClientV3
	}
	_, err := c.Send(ctx, opcode, nil)
	return err
}

// NextKeyID returns the next OpenVPN key epoch id.
// OpenVPN reserves 0 for the initial epoch and then advances
// 0 -> 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 1.
func NextKeyID(current uint8) uint8 {
	next := (current + 1) & KeyIDMask
	if next == 0 {
		return 1
	}
	return next
}

func (c *ControlChannel) KeyID() uint8 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.keyID
}

func (c *ControlChannel) beginEpochLocked(keyID uint8) {
	c.keyID = keyID & KeyIDMask
	c.sendMessage = 0
	c.recvMessage = 0
	c.ackPending = nil
	c.lruAcks = nil
	c.pending = make(map[uint32]*ControlPacket)
	c.recvPending = make(map[uint32]*ControlPacket)
	c.parkedTLS = nil
}

// RotateKeyID advances to the next local key epoch and resets reliable state.
func (c *ControlChannel) RotateKeyID() uint8 {
	c.mu.Lock()
	c.beginEpochLocked(NextKeyID(c.keyID))
	id := c.keyID
	c.mu.Unlock()
	return id
}

// AdoptKeyID switches to the key ID supplied by the peer's soft-reset packet.
func (c *ControlChannel) AdoptKeyID(keyID uint8) {
	c.mu.Lock()
	c.beginEpochLocked(keyID)
	c.mu.Unlock()
}

// QueueAck records a reliable message ID to be acknowledged on the next send.
func (c *ControlChannel) QueueAck(messageID uint32) {
	c.mu.Lock()
	c.ackPending = appendAck(c.ackPending, messageID)
	c.mu.Unlock()
}

// MarkReceived advances the reliable receive sequence past messageID.
// Used after a server soft-reset has already been consumed by the watcher,
// so the new epoch does not wait forever for message 0.
func (c *ControlChannel) MarkReceived(messageID uint32) {
	c.mu.Lock()
	next := messageID + 1
	if next > c.recvMessage {
		c.recvMessage = next
	}
	delete(c.recvPending, messageID)
	c.mu.Unlock()
}

// SendSoftReset sends a P_CONTROL_SOFT_RESET_V1 on the current key epoch.
// Call AdoptKeyID or RotateKeyID first so the packet uses the new key ID.
func (c *ControlChannel) SendSoftReset(ctx context.Context) error {
	_, err := c.Send(ctx, PControlSoftResetV1, nil)
	return err
}

func (c *ControlChannel) Send(ctx context.Context, opcode Opcode, payload []byte) (uint32, error) {
	if !opcode.HasMessageID() {
		return 0, fmt.Errorf("opcode %s cannot carry a reliable message", opcode)
	}

	c.mu.Lock()
	messageID := c.sendMessage
	c.sendMessage++
	// Copy pending acks into the MRU and take up to CONTROL_SEND_ACK_MAX
	// for a reliable control packet, exactly like OpenVPN reliable_ack_write
	// with CONTROL_SEND_ACK_MAX.
	ackIDs := c.takeAcksLocked(controlSendAckMax)
	packet := &ControlPacket{
		Opcode:           opcode,
		KeyID:            c.keyID,
		LocalSession:     c.local,
		AckIDs:           ackIDs,
		AckRemoteSession: c.remote,
		MessageID:        messageID,
		Payload:          cloneBytes(payload),
	}
	c.pending[messageID] = packet
	c.mu.Unlock()

	if err := c.writeControlPacket(ctx, packet); err != nil {
		return 0, err
	}
	return messageID, nil
}

// takeAcksLocked moves ackPending into the MRU and returns up to max ACK IDs
// to place on the outgoing packet. Mirrors OpenVPN copy_acks_to_mru +
// reliable_ack_write: each pending ID is moved to the front of the MRU
// (existing entries shift right; a duplicate is removed), so re-acked IDs are
// not evicted when the MRU is full. The MRU keeps its full capacity; max only
// bounds what is serialized on this packet. Caller must hold c.mu.
func (c *ControlChannel) takeAcksLocked(max int) []uint32 {
	// Consume only the pending ACKs that can be serialized now (like
	// reliable_ack_write): move ackPending[:n] into the MRU front and keep
	// the remainder pending for the next packet. This preserves ACKs that
	// the per-packet cap would otherwise drop.
	n := len(c.ackPending)
	if n > max {
		n = max
	}
	// Move ackPending[:n] (newest last) into the MRU front, preserving their
	// relative order, exactly like copy_acks_to_mru's backward loop.
	for i := n - 1; i >= 0; i-- {
		id := c.ackPending[i]
		move := id
		found := false
		for j := 0; j < len(c.lruAcks); j++ {
			tmp := c.lruAcks[j]
			c.lruAcks[j] = move
			move = tmp
			if move == id {
				found = true
				break
			}
		}
		if !found && len(c.lruAcks) < reliableAckSize {
			c.lruAcks = append(c.lruAcks, move)
		}
	}
	// Retain the unconsumed tail for the next send.
	c.ackPending = c.ackPending[n:]
	if len(c.ackPending) == 0 {
		c.ackPending = nil
	}
	// Cap the MRU at RELIABLE_ACK_SIZE (move-to-front never grows past it).
	if len(c.lruAcks) > reliableAckSize {
		c.lruAcks = c.lruAcks[:reliableAckSize]
	}
	// Serialize from the MRU: up to max, but never more than the MRU holds.
	k := len(c.lruAcks)
	if k > max {
		k = max
	}
	return append([]uint32(nil), c.lruAcks[:k]...)
}

// reliableAckSize mirrors RELIABLE_ACK_SIZE in OpenVPN reliable.h.
const reliableAckSize = 8

// controlSendAckMax mirrors CONTROL_SEND_ACK_MAX in OpenVPN ssl.h: reliable
// control packets carry at most this many ACKs.
const controlSendAckMax = 4

// dedicatedAckMax is the ACK cap for a dedicated P_ACK_V1 packet. OpenVPN
// uses RELIABLE_ACK_SIZE (8) but caps it at 4 when the channel is unprotected
// (TLS_WRAP_NONE, no tls-auth/tls-crypt) for SoftEther compatibility. mihomo
// does not advertise TLS key-material export, so the same cap applies when
// there is no control cryptor.
func (c *ControlChannel) dedicatedAckMax() int {
	if c.crypt == nil {
		return controlSendAckMax
	}
	return reliableAckSize
}

func (c *ControlChannel) SendAck(ctx context.Context) error {
	c.mu.Lock()
	if len(c.ackPending) == 0 {
		c.mu.Unlock()
		return nil
	}
	ackIDs := c.takeAcksLocked(c.dedicatedAckMax())
	packet := &ControlPacket{
		Opcode:           PAckV1,
		KeyID:            c.keyID,
		LocalSession:     c.local,
		AckIDs:           ackIDs,
		AckRemoteSession: c.remote,
	}
	c.mu.Unlock()
	return c.writeControlPacket(ctx, packet)
}

func (c *ControlChannel) Read(ctx context.Context) (*ControlPacket, error) {
	return c.read(ctx, false)
}

func (c *ControlChannel) waitForSoftReset(ctx context.Context) (*ControlPacket, error) {
	c.mu.Lock()
	if c.pendingSoftReset != nil {
		packet := c.pendingSoftReset
		c.pendingSoftReset = nil
		c.mu.Unlock()
		return packet, nil
	}
	c.mu.Unlock()
	for {
		packet, err := c.read(ctx, true)
		if err != nil {
			return nil, err
		}
		if packet.Opcode == PControlSoftResetV1 {
			return packet, nil
		}
		// Same-epoch P_CONTROL_V1 after a rekey is typically a token-only
		// PUSH_REPLY (send_push_reply_auth_token). Park the TLS payload for
		// ReadAll instead of ACK-and-dropping it. read() already ACKed.
		if packet.Opcode == PControlV1 && len(packet.Payload) > 0 {
			c.mu.Lock()
			c.parkedTLS = append(c.parkedTLS, append([]byte(nil), packet.Payload...))
			c.mu.Unlock()
			continue
		}
		if err := c.SendAck(ctx); err != nil {
			return nil, err
		}
	}
}

// ReadAll returns every queued control packet decoded so far, without
// touching the underlying TLS state of the active epoch. Used after key
// exchange so that a TLS-encrypted P_CONTROL_V1 auth-token update is not
// acknowledged and discarded by a raw ControlChannel read. pendingSoftReset
// is deliberately left in place: it is the trigger for the next rekey, not
// TLS payload, and must stay for waitForSoftReset to consume.
func (c *ControlChannel) ReadAll() []*ControlPacket {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.recvPending) + len(c.parkedTLS)
	if n == 0 {
		return nil
	}
	out := make([]*ControlPacket, 0, n)
	for id := c.recvMessage; ; id++ {
		pkt, ok := c.recvPending[id]
		if !ok {
			break
		}
		delete(c.recvPending, id)
		c.recvMessage = id + 1
		out = append(out, pkt)
	}
	for _, payload := range c.parkedTLS {
		out = append(out, &ControlPacket{Opcode: PControlV1, Payload: payload})
	}
	c.parkedTLS = nil
	return out
}

func (c *ControlChannel) read(ctx context.Context, watchSoftReset bool) (*ControlPacket, error) {
	for {
		c.mu.Lock()
		if packet, ok := c.recvPending[c.recvMessage]; ok {
			if watchSoftReset {
				softReset, valid := c.classifyWatchPacketLocked(packet)
				if !valid {
					delete(c.recvPending, c.recvMessage)
					c.mu.Unlock()
					continue
				}
				if softReset {
					delete(c.recvPending, c.recvMessage)
					c.mu.Unlock()
					return packet, nil
				}
			}
			delete(c.recvPending, c.recvMessage)
			c.recvMessage++
			c.mu.Unlock()
			return packet, nil
		}
		c.mu.Unlock()

		raw, err := c.readRawControlPacket(ctx)
		if err != nil {
			return nil, err
		}
		packet, _, _, err := DecodeControlPacket(c.crypt, raw)
		if err != nil {
			if watchSoftReset {
				continue
			}
			return nil, err
		}

		if !watchSoftReset {
			c.mu.Lock()
			curKey := c.keyID
			sameSession := c.remote == (SessionID{}) || packet.LocalSession == c.remote
			if packet.Opcode == PControlSoftResetV1 {
				// Only park a soft reset for the strictly-next epoch. A
				// delayed reset from a retiring epoch must not move the
				// client backwards, and an invalid one must not mutate ACK /
				// pending-message state.
				if packet.KeyID == NextKeyID(curKey) && sameSession {
					if c.pendingSoftReset == nil {
						c.pendingSoftReset = packet
					}
					for _, ackID := range packet.AckIDs {
						delete(c.pending, ackID)
					}
				}
				c.mu.Unlock()
				continue
			}
			if packet.KeyID != curKey {
				c.mu.Unlock()
				// Drop control packets from a retiring key epoch so they
				// cannot be fed into the new TLS session.
				continue
			}
			c.mu.Unlock()
		}

		if watchSoftReset {
			c.mu.Lock()
			softReset, valid := c.classifyWatchPacketLocked(packet)
			c.mu.Unlock()
			if !valid {
				continue
			}
			if softReset {
				return packet, nil
			}
		}

		var deliver *ControlPacket
		sendAck := false

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

		switch {
		case packet.Opcode == PAckV1:
		case !packet.Opcode.HasMessageID():
			deliver = packet
		case packet.MessageID < c.recvMessage:
			sendAck = true
		case packet.MessageID == c.recvMessage:
			deliver = packet
			c.recvMessage++
			sendAck = true
		default:
			if _, exists := c.recvPending[packet.MessageID]; !exists {
				c.recvPending[packet.MessageID] = packet
			}
			sendAck = true
		}
		c.mu.Unlock()

		if sendAck {
			if err := c.SendAck(ctx); err != nil {
				return nil, err
			}
		}

		if deliver != nil {
			return deliver, nil
		}
	}
}

// classifyWatchPacketLocked keeps packets from another session or key epoch
// out of the established control channel. c.mu must be held by the caller.
func (c *ControlChannel) classifyWatchPacketLocked(packet *ControlPacket) (softReset bool, valid bool) {
	if c.remote == (SessionID{}) || packet.LocalSession != c.remote {
		return false, false
	}
	if packet.Opcode == PControlSoftResetV1 {
		// OpenVPN advances 0 -> 1 -> ... -> 7 -> 1. Reject stale or invalid
		// epochs: a delayed reset from a retiring epoch, or key ID 0 after
		// the initial epoch, must not move the client backwards.
		expected := NextKeyID(c.keyID)
		return packet.KeyID == expected, packet.KeyID == expected
	}
	return false, packet.KeyID == c.keyID
}

func (c *ControlChannel) PendingMessages() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}

func (c *ControlChannel) RetransmitPending(ctx context.Context) error {
	c.mu.Lock()
	packets := make([]*ControlPacket, 0, len(c.pending))
	// Pull current acks into the MRU once, so every retransmitted packet
	// carries the same ack set (matching OpenVPN: retransmitted reliable
	// packets reuse the original ack header, and the MRU keeps recently
	// acked IDs alive across sends).
	ackIDs := c.takeAcksLocked(controlSendAckMax)
	for _, packet := range c.pending {
		cp := *packet
		cp.AckIDs = ackIDs
		cp.AckRemoteSession = c.remote
		packets = append(packets, &cp)
	}
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
	if tlsCryptV2, ok := c.crypt.(*TLSCryptV2); ok &&
		packet.Opcode == PControlHardResetClientV3 && packet.MessageID == 0 {
		encoded = append(encoded, tlsCryptV2.WrappedClientKey()...)
	}
	return c.io.WritePacket(ctx, encoded)
}

func (c *ControlChannel) readRawControlPacket(ctx context.Context) ([]byte, error) {
	c.mu.Lock()
	deadline := c.readDeadline
	c.mu.Unlock()

	if !deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}

	return c.io.ReadPacket(ctx)
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

// Reset clears leftover TLS bytes so a new tls.Conn can reuse this adapter.
func (c *ControlConn) Reset() {
	c.mu.Lock()
	c.closed = false
	c.readBuf = nil
	c.mu.Unlock()
}

// UnsafeFeed pushes already-decoded control payload bytes into the TLS
// read buffer. The caller must have drained ReadAll() and must not be
// concurrently reading or writing the tls.Conn. The prefix buffer is
// intentionally NOT the first value so tls.Conn.Read consumes it in order.
func (c *ControlConn) UnsafeFeed(payload []byte) {
	c.mu.Lock()
	c.readBuf = append(c.readBuf, payload...)
	c.mu.Unlock()
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

	// Flush any unacknowledged read BEFORE writing data, so the ACK does not
	// piggyback onto this control message and corrupt the TLS record.
	if err := c.channel.SendAck(context.Background()); err != nil {
		return 0, err
	}
	if _, err := c.channel.Send(context.Background(), PControlV1, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *ControlConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.readBuf = nil
	c.mu.Unlock()
	// The control channel outlives a single TLS epoch. Closing the mux here
	// would tear down the whole OpenVPN transport during a soft reset.
	return nil
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
	conn          net.Conn
	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

type datagramPacketIO struct {
	conn          net.Conn
	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

func NewDatagramPacketIO(conn net.Conn) PacketIO {
	return &datagramPacketIO{conn: conn}
}

func (d *datagramPacketIO) ReadPacket(ctx context.Context) ([]byte, error) {
	if err := setReadDeadlineFromContext(d.conn, ctx, &d.deadlineMu, &d.readDeadline); err != nil {
		return nil, err
	}
	buf := make([]byte, 64*1024)
	n, err := d.conn.Read(buf)
	if err != nil {
		return nil, contextIOError(ctx, err)
	}
	return buf[:n], nil
}

func (d *datagramPacketIO) WritePacket(ctx context.Context, packet []byte) error {
	if err := setWriteDeadlineFromContext(d.conn, ctx, &d.deadlineMu, &d.writeDeadline); err != nil {
		return err
	}
	_, err := d.conn.Write(packet)
	return contextIOError(ctx, err)
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
	if err := setReadDeadlineFromContext(s.conn, ctx, &s.deadlineMu, &s.readDeadline); err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(s.conn, lenBuf[:]); err != nil {
		return nil, contextIOError(ctx, err)
	}
	size := int(lenBuf[0])<<8 | int(lenBuf[1])
	if size == 0 {
		return nil, errors.New("empty openvpn tcp packet")
	}
	packet := make([]byte, size)
	if _, err := io.ReadFull(s.conn, packet); err != nil {
		return nil, contextIOError(ctx, err)
	}
	return packet, nil
}

func (s *streamPacketIO) WritePacket(ctx context.Context, packet []byte) error {
	if len(packet) > 0xffff {
		return fmt.Errorf("openvpn tcp packet too large: %d", len(packet))
	}
	if err := setWriteDeadlineFromContext(s.conn, ctx, &s.deadlineMu, &s.writeDeadline); err != nil {
		return err
	}
	frame := pool.Get(2 + len(packet))
	defer pool.Put(frame)
	frame[0] = byte(len(packet) >> 8)
	frame[1] = byte(len(packet))
	copy(frame[2:], packet)
	_, err := s.conn.Write(frame)
	return contextIOError(ctx, err)
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

func setReadDeadlineFromContext(conn net.Conn, ctx context.Context, mu *sync.Mutex, current *time.Time) error {
	deadline, hasDeadline := ctx.Deadline()
	mu.Lock()
	defer mu.Unlock()
	if current.Equal(deadline) {
		return nil
	}
	if hasDeadline {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return err
		}
	} else if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	*current = deadline
	return nil
}

func setWriteDeadlineFromContext(conn net.Conn, ctx context.Context, mu *sync.Mutex, current *time.Time) error {
	deadline, hasDeadline := ctx.Deadline()
	mu.Lock()
	defer mu.Unlock()
	if current.Equal(deadline) {
		return nil
	}
	if hasDeadline {
		if err := conn.SetWriteDeadline(deadline); err != nil {
			return err
		}
	} else if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		return err
	}
	*current = deadline
	return nil
}

func contextIOError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
