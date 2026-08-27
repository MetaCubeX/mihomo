package openvpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

type ControlIO interface {
	ReadPacket(ctx context.Context) ([]byte, error)
	WritePacket(ctx context.Context, packet []byte) error
	WritePacketAllowActiveStop(ctx context.Context, packet []byte) error
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

type initialPacketReceiver interface {
	markInitialPacketReceived()
}

type ControlChannel struct {
	io          ControlIO
	crypt       ControlCryptor
	clock       func() time.Time
	replayClock func() time.Time
	sendGate    chan struct{}
	keyID       uint8
	local       SessionID
	remote      SessionID

	mu             sync.Mutex
	sendPacketID   uint32
	sendPacketTime uint32
	sendMessage    uint32
	recvMessage    uint32
	ackPending     []uint32
	// lruAcks is the MRU of recently acknowledged packet IDs, mirroring
	// OpenVPN's reliable_ack.lru_acks: acks are copied here when sent and
	// kept so subsequent control packets repeat them until replaced.
	lruAcks     []uint32
	pending     map[uint32]*ControlPacket
	recvPending map[uint32]*ControlPacket
	// pendingSoftReset holds a server soft-reset that arrived while the
	// current epoch was still doing TLS/key-method. waitForSoftReset
	// consumes it so ControlConn.Read cannot swallow it.
	pendingSoftReset *ControlPacket
	// parkedTLS holds same-epoch P_CONTROL_V1 payloads that arrived while
	// the watcher was waiting for a soft reset (typically a token-only
	// PUSH_REPLY). ReadAll drains them into leftoverTLS / tls.Conn.
	parkedTLS               [][]byte
	readDeadline            time.Time
	writeDeadline           time.Time
	writeCancel             context.CancelCauseFunc
	writeTimer              *time.Timer
	writeDeadlineGeneration uint64
	writeGeneration         uint64
	readWake                chan struct{}
	ackWake                 chan struct{}
	// recReplay is the session-wide anti-replay window for tls-auth / tls-crypt
	// protected control packets, mirroring OpenVPN's packet_id_rec. Soft key
	// resets do not replace the outer TLS wrapper or reset its packet IDs.
	recReplay replayState
}

// replayState is the receive-side OpenVPN long-form packet-id window.
// slots are indexed by distance behind highID: 0 unseen, 1 expired, >1 local
// acceptance time in Unix nanoseconds. Gaps age out after timeBacktrack.
type replayState struct {
	time   uint32
	highID uint32
	slots  [controlReplayWindow]int64
	seen   bool
}

// controlReplayWindow mirrors OpenVPN's REPLAY_WINDOW (64) used for the
// control-channel packet_id_rec seq_backtrack.
const controlReplayWindow = 64
const controlReplayTimeBacktrack = 15 * time.Second

// recvWindowOK reports whether an out-of-order control packet with the given
// message ID fits the receive window. Unsigned subtraction mirrors OpenVPN's
// reliable_pid_in_range1 and remains correct when the 32-bit sequence wraps.
func recvWindowOK(recvMessage, messageID uint32, buffered int) bool {
	return messageID-recvMessage < reliableCapacity && buffered < reliableCapacity
}

func reliableMessageBefore(messageID, recvMessage uint32) bool {
	return messageID-recvMessage >= uint32(1)<<31
}

// checkReplay validates a protected control packet's packet-id/timestamp
// against the anti-replay window. Returns an error for replayed or stale
// packets. Must be called with c.mu held.
func (c *ControlChannel) checkReplayLocked(packetID, unixTime uint32) error {
	if packetID == 0 {
		return errors.New("openvpn control replay: packet id 0")
	}
	r := &c.recReplay
	replayClock := c.replayClock
	if replayClock == nil {
		replayClock = time.Now
	}
	now := replayClock()
	if !r.seen || unixTime > r.time {
		*r = replayState{time: unixTime, highID: packetID, seen: true}
		r.slots[0] = now.UnixNano()
		return nil
	}
	if unixTime < r.time {
		return fmt.Errorf("openvpn control replay: timestamp backtrack %d < %d", unixTime, r.time)
	}
	r.reap(now)
	if packetID > r.highID {
		shift := int(packetID - r.highID)
		if shift >= controlReplayWindow {
			r.slots = [controlReplayWindow]int64{}
		} else {
			for i := controlReplayWindow - 1; i >= shift; i-- {
				r.slots[i] = r.slots[i-shift]
			}
			for i := 0; i < shift; i++ {
				r.slots[i] = 0
			}
		}
		r.highID = packetID
		r.slots[0] = now.UnixNano()
		return nil
	}
	diff := r.highID - packetID
	if diff >= controlReplayWindow {
		return fmt.Errorf("openvpn control replay: stale packet id %d", packetID)
	}
	slot := r.slots[diff]
	if slot != 0 {
		return fmt.Errorf("openvpn control replay: replayed or expired packet id %d", packetID)
	}
	r.slots[diff] = now.UnixNano()
	return nil
}

func (r *replayState) reap(now time.Time) {
	expire := false
	for i, accepted := range r.slots {
		if accepted == 1 {
			break
		}
		if !expire && accepted > 1 && time.Unix(0, accepted).Add(controlReplayTimeBacktrack).Before(now) {
			expire = true
		}
		if expire {
			r.slots[i] = 1
		}
	}
}

func NewControlChannel(io ControlIO, crypt ControlCryptor, local SessionID) *ControlChannel {
	return &ControlChannel{
		io:          io,
		crypt:       crypt,
		clock:       time.Now,
		replayClock: time.Now,
		sendGate:    make(chan struct{}, 1),
		local:       local,
		pending:     make(map[uint32]*ControlPacket),
		recvPending: make(map[uint32]*ControlPacket),
		readWake:    make(chan struct{}),
		ackWake:     make(chan struct{}, 1),
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
	c.signalAckLocked()
	c.mu.Unlock()
}

func (c *ControlChannel) signalAckLocked() {
	select {
	case c.ackWake <- struct{}{}:
	default:
	}
}

func (c *ControlChannel) signalAck() {
	c.mu.Lock()
	c.signalAckLocked()
	c.mu.Unlock()
}

func (c *ControlChannel) PendingACKs() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.ackPending)
}

// MarkReceived advances the reliable receive sequence past messageID.
// Used after a server soft-reset has already been consumed by the watcher,
// so the new epoch does not wait forever for message 0.
func (c *ControlChannel) MarkReceived(messageID uint32) {
	c.mu.Lock()
	next := messageID + 1
	if next != c.recvMessage && !reliableMessageBefore(next, c.recvMessage) {
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

// reliableCapacity mirrors the receive reliable buffer capacity in OpenVPN:
// TLS_RELIABLE_N_REC_BUFFERS with RELIABLE_CAPACITY=12. It bounds how many
// out-of-order control packets mihomo will buffer before they can be
// delivered in sequence.
const reliableCapacity = 12

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
	// Select the ACK IDs and key epoch only after this write owns the logical
	// send gate. This keeps an asynchronous ACK from being constructed for an
	// old epoch and emitted after a new epoch's first reliable packet.
	c.mu.Lock()
	hasPending := len(c.ackPending) != 0
	c.mu.Unlock()
	if !hasPending {
		return nil
	}
	if err := acquireWriteGate(ctx, c.sendGate); err != nil {
		return err
	}
	defer releaseWriteGate(c.sendGate)
	if err := ctx.Err(); err != nil {
		return err
	}
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
	return c.writeControlPacketGranted(ctx, packet, true)
}

func (c *ControlChannel) Read(ctx context.Context) (*ControlPacket, error) {
	return c.read(ctx, false)
}

// errParkedTLS is returned by waitForSoftReset when it parked a same-epoch
// TLS control payload (token update / AUTH_FAILED) that must be consumed
// before continuing to wait for the next soft reset.
var errParkedTLS = errors.New("parked tls control payload")

func (c *ControlChannel) waitForSoftReset(ctx context.Context) (*ControlPacket, error) {
	c.mu.Lock()
	if c.pendingSoftReset != nil {
		packet := c.pendingSoftReset
		c.pendingSoftReset = nil
		// Defensive: a parked reset must be the strictly-next epoch and
		// message 0; drop it otherwise (never advance the receive sequence
		// off an invalid reset).
		expected := NextKeyID(c.keyID)
		if packet.KeyID != expected || packet.MessageID != 0 {
			c.mu.Unlock()
			goto read
		}
		c.mu.Unlock()
		return packet, nil
	}
	c.mu.Unlock()
read:
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
		// ReadAll instead of ACK-and-dropping it, and return so the caller
		// consumes it immediately (a late AUTH_FAILED must not wait for the
		// next soft reset). read() already ACKed.
		if packet.Opcode == PControlV1 && len(packet.Payload) > 0 {
			c.mu.Lock()
			c.parkedTLS = append(c.parkedTLS, append([]byte(nil), packet.Payload...))
			c.mu.Unlock()
			return nil, errParkedTLS
		}
		c.signalAck()
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
	// parkedTLS payloads were received out of order and already advanced
	// recvMessage, so they logically precede any newly contiguous recvPending
	// entries. Emit them first to keep the TLS byte stream in order after
	// UDP reordering.
	for _, payload := range c.parkedTLS {
		out = append(out, &ControlPacket{Opcode: PControlV1, Payload: payload})
	}
	c.parkedTLS = nil
	for id := c.recvMessage; ; id++ {
		pkt, ok := c.recvPending[id]
		if !ok {
			break
		}
		delete(c.recvPending, id)
		c.recvMessage = id + 1
		out = append(out, pkt)
	}
	return out
}

func (c *ControlChannel) read(ctx context.Context, watchSoftReset bool) (*ControlPacket, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
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
		packet, packetID, unixTime, err := DecodeControlPacket(c.crypt, raw)
		if err != nil {
			// Invalid control datagrams are packet loss, not TLS stream errors.
			// OpenVPN drops malformed/authentication-failed packets and keeps the
			// reliable read alive for a valid retransmission.
			continue
		}

		if packet.LocalSession == (SessionID{}) {
			continue
		}
		if len(packet.AckIDs) > 0 && packet.AckRemoteSession != c.local {
			continue
		}
		replayChecked := false
		c.mu.Lock()
		remote := c.remote
		if remote == (SessionID{}) {
			initialReset := (packet.Opcode == PControlHardResetServerV2 ||
				packet.Opcode == PControlHardResetServerV1) &&
				packet.KeyID == c.keyID && packet.MessageID == 0
			if initialReset && c.crypt != nil {
				if err := c.checkReplayLocked(packetID, unixTime); err != nil {
					c.mu.Unlock()
					continue
				}
				replayChecked = true
			}
			if initialReset {
				c.remote = packet.LocalSession
				remote = packet.LocalSession
				if receiver, ok := c.io.(initialPacketReceiver); ok {
					receiver.markInitialPacketReceived()
				}
			}
		}
		c.mu.Unlock()
		if remote == (SessionID{}) || packet.LocalSession != remote {
			continue
		}

		if !watchSoftReset {
			c.mu.Lock()
			curKey := c.keyID
			sameSession := c.remote == (SessionID{}) || packet.LocalSession == c.remote
			if packet.Opcode == PControlSoftResetV1 {
				// Only park a soft reset for the strictly-next epoch and
				// message 0 (a new-epoch reset is always message 0). A
				// delayed reset from a retiring epoch must not move the
				// client backwards, and an invalid one must not mutate ACK /
				// pending-message state.
				if packet.KeyID == NextKeyID(curKey) && packet.MessageID == 0 && sameSession {
					// tls-auth/tls-crypt packet IDs belong to the outer TLS
					// session and remain continuous across key-state soft resets.
					if c.crypt != nil {
						if err := c.checkReplayLocked(packetID, unixTime); err != nil {
							c.mu.Unlock()
							continue
						}
					}
					packet.receivedAt = time.Now()
					// Only one future key state can be negotiated at a time. A
					// second distinct reset would require the peer to advance again
					// before this epoch completed; keep the first trigger and drop
					// that theoretical protocol violation. Retransmissions of the
					// same reset are acknowledged through the normal ACK state.
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
			if c.crypt != nil && !replayChecked {
				if err := c.checkReplayLocked(packetID, unixTime); err != nil {
					c.mu.Unlock()
					continue
				}
			}
			c.mu.Unlock()
		}

		if watchSoftReset {
			c.mu.Lock()
			softReset, valid := c.classifyWatchPacketLocked(packet)
			if !valid {
				c.mu.Unlock()
				continue
			}
			if softReset {
				if c.crypt != nil {
					if err := c.checkReplayLocked(packetID, unixTime); err != nil {
						c.mu.Unlock()
						continue
					}
				}
				packet.receivedAt = time.Now()
				c.mu.Unlock()
				return packet, nil
			}
			if c.crypt != nil {
				if err := c.checkReplayLocked(packetID, unixTime); err != nil {
					c.mu.Unlock()
					continue
				}
			}
			c.mu.Unlock()
		}

		var deliver *ControlPacket

		c.mu.Lock()
		for _, ackID := range packet.AckIDs {
			delete(c.pending, ackID)
		}

		// OpenVPN read_control_auth: a message ID is acknowledged only when
		// the packet is accepted into the receive window (reliable_wont_break
		// _sequentiality succeeds), whether it is new or an in-window replay.
		// A packet that would break the receive window is neither buffered nor
		// acknowledged, so the sender keeps it for retransmission and the
		// reliable stream never develops a permanent hole.
		switch {
		case packet.Opcode == PAckV1:
		case !packet.Opcode.HasMessageID():
			deliver = packet
		case reliableMessageBefore(packet.MessageID, c.recvMessage):
			// In-window replay of an already-delivered packet: acknowledge so
			// the sender stops retransmitting, but do not redeliver.
			c.ackPending = appendAck(c.ackPending, packet.MessageID)
			c.signalAckLocked()
		case packet.MessageID == c.recvMessage:
			// The expected next message: deliver and advance.
			c.ackPending = appendAck(c.ackPending, packet.MessageID)
			c.signalAckLocked()
			deliver = packet
			c.recvMessage++
		default:
			// Out-of-order packet ahead of recvMessage. A duplicate already
			// buffered inside the receive window must be re-ACKed (its first
			// ACK may have been lost) without re-inserting it. A new packet is
			// buffered and ACKed only if it fits the bounded window; a rejected
			// out-of-window packet is neither buffered nor ACKed.
			if _, exists := c.recvPending[packet.MessageID]; exists {
				c.ackPending = appendAck(c.ackPending, packet.MessageID)
				c.signalAckLocked()
			} else if recvWindowOK(c.recvMessage, packet.MessageID, len(c.recvPending)) {
				c.recvPending[packet.MessageID] = packet
				c.ackPending = appendAck(c.ackPending, packet.MessageID)
				c.signalAckLocked()
			}
		}
		c.mu.Unlock()

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
		// the initial epoch, must not move the client backwards. A new-epoch
		// reset is always message 0 (the fresh reliable layer starts at 0);
		// any other ID would corrupt the receive sequence and is invalid.
		expected := NextKeyID(c.keyID)
		return packet.KeyID == expected && packet.MessageID == 0,
			packet.KeyID == expected && packet.MessageID == 0
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
	// Nothing to retransmit: do not consume pending ACKs (moving them into
	// the MRU without emitting a packet would drop them).
	if len(c.pending) == 0 {
		c.mu.Unlock()
		return nil
	}
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
		if err := c.writeControlPacketWithAbort(ctx, packet, false); err != nil {
			return err
		}
	}
	return nil
}

func (c *ControlChannel) writeControlPacket(ctx context.Context, packet *ControlPacket) error {
	return c.writeControlPacketWithAbort(ctx, packet, true)
}

func (c *ControlChannel) writeControlPacketWithAbort(ctx context.Context, packet *ControlPacket, abortActive bool) error {
	if err := acquireWriteGate(ctx, c.sendGate); err != nil {
		return err
	}
	defer releaseWriteGate(c.sendGate)
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.writeControlPacketGranted(ctx, packet, abortActive)
}

// writeControlPacketGranted writes while the caller owns sendGate.
func (c *ControlChannel) writeControlPacketGranted(ctx context.Context, packet *ControlPacket, abortActive bool) error {
	c.mu.Lock()
	if c.crypt != nil && c.sendPacketID == ^uint32(0) {
		c.mu.Unlock()
		return errors.New("openvpn control packet id exhausted; new session required")
	}
	if c.crypt != nil && c.sendPacketTime == 0 {
		c.sendPacketTime = uint32(c.clock().Unix())
	}
	c.sendPacketID++
	packetID := c.sendPacketID
	unixTime := c.sendPacketTime
	opCtx, cancel := context.WithCancelCause(ctx)
	c.writeGeneration++
	generation := c.writeGeneration
	c.writeCancel = cancel
	c.scheduleWriteDeadlineLocked()
	c.mu.Unlock()
	defer c.finishWrite(generation, cancel)

	encoded, err := packet.Encode(c.crypt, packetID, unixTime)
	if err != nil {
		return err
	}
	if err := opCtx.Err(); err != nil {
		if cause := context.Cause(opCtx); cause != nil {
			return cause
		}
		return err
	}
	if tlsCryptV2, ok := c.crypt.(*TLSCryptV2); ok &&
		packet.Opcode == PControlHardResetClientV3 && packet.MessageID == 0 {
		encoded = append(encoded, tlsCryptV2.WrappedClientKey()...)
	}
	if abortActive {
		err = c.io.WritePacket(opCtx, encoded)
	} else {
		err = c.io.WritePacketAllowActiveStop(opCtx, encoded)
	}
	if err != nil && opCtx.Err() != nil {
		if cause := context.Cause(opCtx); cause != nil {
			return cause
		}
		return err
	}
	if errors.Is(err, errPacketDropped) {
		return nil
	}
	return err
}

func (c *ControlChannel) readRawControlPacket(ctx context.Context) ([]byte, error) {
	for {
		c.mu.Lock()
		deadline := c.readDeadline
		if c.readWake == nil {
			c.readWake = make(chan struct{})
		}
		wake := c.readWake
		c.mu.Unlock()

		opCtx, cancel := context.WithCancel(ctx)
		deadlineCancel := func() {}
		if !deadline.IsZero() {
			opCtx, deadlineCancel = context.WithDeadline(opCtx, deadline)
		}
		wakeDone := make(chan struct{})
		go func() {
			defer close(wakeDone)
			select {
			case <-wake:
				cancel()
			case <-opCtx.Done():
			}
		}()
		raw, err := c.io.ReadPacket(opCtx)
		cancel()
		deadlineCancel()
		<-wakeDone

		c.mu.Lock()
		changed := wake != c.readWake
		c.mu.Unlock()
		if err == nil {
			return raw, nil
		}
		if changed && ctx.Err() == nil {
			continue
		}
		return raw, err
	}
}

func (c *ControlChannel) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.signalReadWakeLocked()
	c.scheduleWriteDeadlineLocked()
	c.mu.Unlock()
	return nil
}

func (c *ControlChannel) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.signalReadWakeLocked()
	c.mu.Unlock()
	return nil
}

func (c *ControlChannel) signalReadWakeLocked() {
	if c.readWake != nil {
		close(c.readWake)
	}
	c.readWake = make(chan struct{})
}

func (c *ControlChannel) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.scheduleWriteDeadlineLocked()
	c.mu.Unlock()
	return nil
}

func (c *ControlChannel) scheduleWriteDeadlineLocked() {
	c.writeDeadlineGeneration++
	if c.writeTimer != nil {
		c.writeTimer.Stop()
		c.writeTimer = nil
	}
	if c.writeCancel == nil || c.writeDeadline.IsZero() {
		return
	}
	writeGeneration := c.writeGeneration
	deadlineGeneration := c.writeDeadlineGeneration
	cancel := c.writeCancel
	delay := time.Until(c.writeDeadline)
	if delay <= 0 {
		cancel(context.DeadlineExceeded)
		return
	}
	c.writeTimer = time.AfterFunc(delay, func() {
		c.cancelWriteGeneration(writeGeneration, deadlineGeneration, cancel)
	})
}

func (c *ControlChannel) cancelWriteGeneration(writeGeneration, deadlineGeneration uint64, cancel context.CancelCauseFunc) {
	c.mu.Lock()
	if c.writeGeneration == writeGeneration &&
		c.writeDeadlineGeneration == deadlineGeneration && c.writeCancel != nil {
		cancel(context.DeadlineExceeded)
	}
	c.mu.Unlock()
}

func (c *ControlChannel) finishWrite(generation uint64, cancel context.CancelCauseFunc) {
	cancel(context.Canceled)
	c.mu.Lock()
	if c.writeGeneration == generation {
		if c.writeTimer != nil {
			c.writeTimer.Stop()
			c.writeTimer = nil
		}
		c.writeCancel = nil
	}
	c.mu.Unlock()
}

func (c *ControlChannel) interruptWrite() {
	c.mu.Lock()
	if c.writeCancel != nil {
		c.writeCancel(context.Canceled)
	}
	c.mu.Unlock()
}

func appendAck(acks []uint32, ack uint32) []uint32 {
	for _, existing := range acks {
		if existing == ack {
			return acks
		}
	}
	return append(acks, ack)
}

// maxTLSControlPayload keeps each default OpenVPN control datagram below
// TLS_MTU_DEFAULT (1250) even with tls-auth/tls-crypt and four piggyback ACKs.
// OpenVPN splits TLS ciphertext before placing it in the reliable channel;
// crypto/tls may otherwise hand Write a record much larger than one datagram.
const maxTLSControlPayload = 1100

type ControlConn struct {
	channel  *ControlChannel
	readBuf  []byte
	closed   bool
	mu       sync.Mutex
	writeMu  sync.Mutex
	opCtx    context.Context
	opCancel context.CancelFunc
}

func NewControlConn(channel *ControlChannel) *ControlConn {
	opCtx, opCancel := context.WithCancel(context.Background())
	return &ControlConn{channel: channel, opCtx: opCtx, opCancel: opCancel}
}

func (c *ControlConn) Reset() {
	c.mu.Lock()
	if c.opCancel != nil {
		c.opCancel()
	}
	c.opCtx, c.opCancel = context.WithCancel(context.Background())
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
	opCtx := c.opCtx
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()

	for {
		packet, err := c.channel.Read(opCtx)
		if err != nil {
			c.mu.Lock()
			closed := c.closed
			c.mu.Unlock()
			if closed {
				return 0, net.ErrClosed
			}
			return 0, err
		}
		if packet.Opcode != PControlV1 {
			continue
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
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	opCtx := c.opCtx
	c.mu.Unlock()

	// Flush any unacknowledged read BEFORE writing data, so the ACK does not
	// piggyback onto this control message and corrupt the TLS record.
	if err := c.channel.SendAck(opCtx); err != nil {
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return 0, net.ErrClosed
		}
		return 0, err
	}
	// Close may race with a successfully completed ACK write. Never begin the
	// TLS payload write after the adapter has been closed.
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	written := 0
	for len(b) > 0 {
		n := len(b)
		if n > maxTLSControlPayload {
			n = maxTLSControlPayload
		}
		if _, err := c.channel.Send(opCtx, PControlV1, b[:n]); err != nil {
			c.mu.Lock()
			closed := c.closed
			c.mu.Unlock()
			if closed {
				return written, net.ErrClosed
			}
			return written, err
		}
		written += n
		b = b[n:]
	}
	return written, nil
}

func (c *ControlConn) Close() error {
	c.mu.Lock()
	c.closed = true
	if c.opCancel != nil {
		c.opCancel()
	}
	c.readBuf = nil
	c.channel.interruptWrite()
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

func acquireWriteGate(ctx context.Context, gate chan struct{}) error {
	select {
	case gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func releaseWriteGate(gate chan struct{}) {
	<-gate
}
