package miu

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/transport/anytls/padding"
)

// lane is one authenticated connection: a TCP connection, the outer TLS on top of it, and one
// authentication. It carries a single stream at a time and goes back to the pool when that stream ends.
//
// Two things alternate on a lane: frames inside outer TLS records, and raw segments, bytes that follow a
// RAW frame directly on TCP without going through the outer TLS (inner data that already is TLS 1.3
// ciphertext is not encrypted a second time). Each side of a lane is read by one goroutine at a time;
// writes are serialized by wmu.
type lane struct {
	conn net.Conn // frames
	sock net.Conn // the socket under conn (conn itself when the outer layer is not TLS): raw segments, liveness probe
	in   *bytes.Reader
	rin  *bytes.Buffer
	// canRaw: this side can enter and leave raw segments (the outer layer is a Go TLS connection whose
	// buffers are reachable). peerRaw: the peer has declared raw=1 in its settings.
	canRaw  bool
	peerRaw atomic.Bool
	server  bool
	client  *Client

	wmu sync.Mutex
	// prefix is written at the very start of the next write, in the same record: the client's
	// authentication header and Settings (they wait for the lane's first use), the server's
	// ServerSettings. prefixTimer writes it alone if nothing else is written in time. Guarded by wmu.
	prefix      []byte
	prefixTimer *time.Timer
	// sent counts the packets written on the lane in its sending direction (writeLanePacket): only the
	// lane's first ones are shaped, whatever stream they belong to. Guarded by wmu.
	sent uint32
	// base is the scheme whose md5 is exchanged in Settings: the PSK-derived one or an explicit one. The
	// lane shapes with scheme, which is its own draw from base's family when base is derived.
	base *padding.PaddingFactory
	// idle is how long the server keeps this lane without a stream (server only; jittered per lane).
	idle time.Duration
	// Client only. unauthed: the authentication header is still in prefix (the lane has not been used
	// yet); preauthTTL is how long such a lane may wait in the pool, below the server's handshake
	// timeout; idleScale spreads the idle time of the used lane.
	unauthed   atomic.Bool
	preauthTTL time.Duration
	idleScale  float64

	scheme atomic.Pointer[padding.PaddingFactory]
	closed atomic.Bool
	done   chan struct{} // closed by close

	// peerIdle is how many seconds the server keeps an idle lane (client side).
	peerIdle atomic.Int64

	// Read cursor. A read that fails with a timeout leaves it intact, so the read can be retried.
	head     [frameHead]byte
	headN    int
	body     []byte // payload of the frame being gathered (everything except DATA and raw bytes)
	bodyN    int
	dataLeft int   // unread bytes of the current DATA frame
	rawLeft  int64 // unread bytes of the current raw segment
}

func newLane(conn net.Conn, server, allowRaw bool) *lane {
	l := &lane{conn: conn, sock: conn, server: server, done: make(chan struct{})}
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &l.scheme)
	if in, rin, sock, ok := tlsBuffers(conn); ok {
		l.sock = sock
		if allowRaw {
			l.in, l.rin, l.canRaw = in, rin, true
		}
	}
	return l
}

func (l *lane) close() {
	if l.closed.CompareAndSwap(false, true) {
		close(l.done)
		l.conn.Close()
	}
}

func (l *lane) event(name string) {
	if testObserver.Load() == nil {
		return
	}
	if l.server {
		observe("server:" + name)
	} else {
		observe("client:" + name)
	}
}

// ---- reading ----

// fill reads into p until *got reaches len(p). Progress survives an error.
// Frames are read on demand, never ahead: entering a raw segment requires the read position to line up
// with the TLS records.
func (l *lane) fill(p []byte, got *int) error {
	for *got < len(p) {
		n, err := l.conn.Read(p[*got:])
		*got += n
		if err != nil && *got < len(p) {
			return err
		}
	}
	return nil
}

// next reads up to the next frame the caller has to act on and returns its type.
//
//   - frData / frRaw: the payload is pending; fetch it with readPayload until pending() is false.
//   - anything else: payload is the complete frame body, valid until the next call.
//
// PAD frames are skipped. The call can be repeated after a timeout.
func (l *lane) next() (typ byte, payload []byte, err error) {
	for {
		if err = l.fill(l.head[:], &l.headN); err != nil {
			return 0, nil, err
		}
		typ, n := l.head[0], int(l.head[1])<<8|int(l.head[2])
		switch typ {
		case frData:
			l.headN = 0
			if n == 0 {
				continue
			}
			l.dataLeft = n
			return frData, nil, nil
		case frRaw:
			size, err := l.readRawLen(n)
			if err != nil {
				return 0, nil, err
			}
			l.headN = 0
			if size == 0 {
				continue
			}
			l.rawLeft = size
			l.event("rawin")
			return frRaw, nil, nil
		}
		if l.body == nil {
			l.body, l.bodyN = make([]byte, n), 0
		}
		if err = l.fill(l.body, &l.bodyN); err != nil {
			return 0, nil, err
		}
		payload, l.body, l.headN = l.body, nil, 0
		if typ != frPad {
			return typ, payload, nil
		}
	}
}

// readRawLen reads the body of a RAW frame (a u32).
//
// RAW is the last frame of its record and raw bytes follow it. A Go TLS connection's Read, once it has
// emptied a record, peeks at the first byte of rawInput and parses an alert record if it is 0x15 — but
// here that byte is raw data and can be anything. So the last byte does not go through Read: the first
// three are read normally (one byte is left in input, so no peek happens) and the last one is taken
// straight out of input.
func (l *lane) readRawLen(n int) (int64, error) {
	if n != 4 || !l.canRaw {
		return 0, errors.New("miu: unexpected RAW frame")
	}
	if l.body == nil {
		l.body, l.bodyN = make([]byte, 4), 0
	}
	if err := l.fill(l.body[:3], &l.bodyN); err != nil {
		return 0, err
	}
	b, err := l.in.ReadByte()
	if err != nil || l.in.Len() != 0 {
		return 0, errors.New("miu: RAW frame is not the last frame of its record")
	}
	l.body[3] = b
	size := int64(binary.BigEndian.Uint32(l.body))
	l.body = nil
	return size, nil
}

// pending reports whether payload of the current DATA frame or raw segment is still unread.
func (l *lane) pending() bool { return l.dataLeft > 0 || l.rawLeft > 0 }

// readPayload reads some of the pending payload into p. Raw bytes come first from what the TLS
// connection has already read off the socket, then from the socket itself — never more than the segment
// holds, so nothing that belongs to the next TLS record is taken.
func (l *lane) readPayload(p []byte) (n int, err error) {
	switch {
	case l.dataLeft > 0:
		if len(p) > l.dataLeft {
			p = p[:l.dataLeft]
		}
		n, err = l.conn.Read(p)
		l.dataLeft -= n
	case l.rawLeft > 0:
		if int64(len(p)) > l.rawLeft {
			p = p[:l.rawLeft]
		}
		if l.rin.Len() > 0 {
			n, _ = l.rin.Read(p)
		} else {
			n, err = l.sock.Read(p)
		}
		l.rawLeft -= int64(n)
	}
	if n > 0 {
		err = nil
	}
	return n, err
}

// control handles the frames a client can receive at any point: ServerSettings and UpdatePaddingScheme.
func (l *lane) control(typ byte, payload []byte) error {
	switch typ {
	case frServerSettings:
		kv := parseKV(string(payload))
		l.peerRaw.Store(kv["raw"] == "1")
		if idle, ok := kvInt(kv, "idle"); ok && idle > 0 {
			l.peerIdle.Store(idle)
		}
	case frUpdatePadding:
		if padding.UpdatePaddingScheme(payload, &l.scheme) && l.client != nil {
			l.client.updatePadding(l.scheme.Load())
		}
	default:
		return fmt.Errorf("miu: unexpected frame type %d", typ)
	}
	return nil
}

// discardToEnd reads the downlink up to and including END, dropping the payload (client side).
func (l *lane) discardToEnd() error {
	buf := pool.Get(pool.RelayBufferSize)
	defer pool.Put(buf)
	for {
		for l.pending() {
			if _, err := l.readPayload(buf); err != nil {
				return err
			}
		}
		typ, payload, err := l.next()
		if err != nil {
			return err
		}
		switch typ {
		case frData, frRaw:
		case frEnd:
			return nil
		default:
			if err := l.control(typ, payload); err != nil {
				return err
			}
		}
	}
}

// ---- writing ----

// write writes p, preceded by the pending prefix if there is one. Caller holds wmu (or owns the lane).
func (l *lane) write(p []byte) error {
	if len(l.prefix) > 0 {
		p = append(l.prefix[:len(l.prefix):len(l.prefix)], p...)
		l.prefix = nil
		if !l.server {
			l.unauthed.Store(false)
		}
		if l.prefixTimer != nil {
			l.prefixTimer.Stop()
		}
	}
	_, err := l.conn.Write(p)
	return err
}

// deferPrefix queues b to go out at the start of the next write; if nothing is written within wait, it
// goes alone (padded like any small record).
func (l *lane) deferPrefix(b []byte, wait time.Duration) {
	l.wmu.Lock()
	defer l.wmu.Unlock()
	l.prefix = append(l.prefix, b...)
	if l.prefixTimer == nil {
		l.prefixTimer = time.AfterFunc(wait, l.flushPrefixLocked)
	} else {
		l.prefixTimer.Reset(wait)
	}
}

func (l *lane) flushPrefixLocked() {
	l.wmu.Lock()
	defer l.wmu.Unlock()
	if err := l.flushPrefix(); err != nil {
		l.close()
	}
}

// flushPrefix writes a pending prefix on its own. Caller holds wmu.
func (l *lane) flushPrefix() error {
	if len(l.prefix) == 0 || l.closed.Load() {
		return nil
	}
	return l.write(l.padSmall(nil))
}

func (l *lane) writeFrame(typ byte, payload []byte) error {
	l.wmu.Lock()
	defer l.wmu.Unlock()
	return l.write(l.padSmall(appendFrame(make([]byte, 0, frameHead+len(payload)), typ, payload)))
}

// writeUnshaped writes already encoded frames as they are, padded if they make a small record.
func (l *lane) writeUnshaped(p []byte) error {
	l.wmu.Lock()
	defer l.wmu.Unlock()
	return l.write(l.padSmall(p))
}

// writeLanePacket sends one "packet" (a few encoded frames) as the lane's next one. Packets are counted
// per lane, not per stream: the shaping covers the start of the lane only. Shaping every stream the same
// way would repeat the scheme's lengths at the start of every stream a lane carries, which is easy to see.
func (l *lane) writeLanePacket(p []byte) error {
	l.wmu.Lock()
	defer l.wmu.Unlock()
	l.sent++
	return l.writePacketLocked(l.sent, p)
}

// writePacket sends one "packet" (a few encoded frames). While pkt is below the scheme's stop, the packet
// is cut into TLS records of the prescribed lengths, the last one filled up with a PAD frame; otherwise it
// goes out in one write. A cut may fall inside a frame: the peer parses frames from the byte stream.
func (l *lane) writePacket(pkt uint32, p []byte) error {
	l.wmu.Lock()
	defer l.wmu.Unlock()
	return l.writePacketLocked(pkt, p)
}

func (l *lane) writePacketLocked(pkt uint32, p []byte) error {
	var sizes []int
	if scheme := l.scheme.Load(); pkt < scheme.Stop {
		sizes = scheme.GenerateRecordPayloadSizes(pkt)
	}
	for _, size := range sizes {
		if size == padding.CheckMark {
			if len(p) == 0 {
				break
			}
			continue
		}
		if size <= frameHead || size >= 8192 {
			break // broken scheme: the rest goes out unshaped
		}
		switch {
		case len(p) > size:
			if err := l.write(p[:size]); err != nil {
				return err
			}
			p = p[size:]
		case len(p) > 0:
			if pad := size - len(p) - frameHead; pad > 0 {
				p = appendFrame(p[:len(p):len(p)], frPad, make([]byte, pad))
			}
			if err := l.write(p); err != nil {
				return err
			}
			p = nil
		default:
			if err := l.write(appendFrame(nil, frPad, make([]byte, size))); err != nil {
				return err
			}
		}
	}
	if len(p) > 0 {
		return l.write(p)
	}
	return nil
}

// writeRawHeader writes the record announcing a raw segment: the RAW frame, which has to be the last
// frame of its record, padded in front like any small record (it would otherwise always be the same few
// dozen bytes long, before every segment). n raw bytes follow. Caller holds wmu.
func (l *lane) writeRawHeader(n int) error {
	return l.writeRawHeaderAfter(nil, n)
}

// writeRawHeaderAfter writes lead (encoded frames) and the RAW frame for n bytes as one record.
func (l *lane) writeRawHeaderAfter(lead []byte, n int) error {
	hdr := append(lead, frRaw, 0, 4, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(hdr[len(hdr)-4:], uint32(n))
	return l.write(l.padSmall(hdr))
}

// firstRecordLen returns the length, header included, of the TLS record at the start of a followed by
// b; 0 when the header is not all there.
func firstRecordLen(a, b []byte) int {
	var h [5]byte
	k := copy(h[:], a)
	if copy(h[k:], b) < 5-k {
		return 0
	}
	return 5 + int(binary.BigEndian.Uint16(h[3:]))
}

// maxPlain is the most plaintext one TLS record carries.
const maxPlain = 16384

// writeRaw sends p as raw segments, cut every maxSeg bytes regardless of what p holds (the self-test);
// streams use writeRawRecords.
func (l *lane) writeRaw(p []byte) error {
	for len(p) > 0 {
		seg := p[:minInt(len(p), maxSeg)]
		p = p[len(seg):]
		if err := l.writeRawRecords(seg, nil); err != nil {
			return err
		}
	}
	return nil
}

// writeRawRecords sends a followed by b as one raw segment. Callers pass whole inner TLS records, at
// most maxSeg bytes in all.
//
// When the first of those records fits, it goes inside the record that announces the segment, as DATA
// in front of the RAW frame: the announcement is then not a small record of its own ahead of every
// segment, but a record about as long as an inner one. A full-size inner record does not fit; then the
// announcement stands alone (padded like any small record).
func (l *lane) writeRawRecords(a, b []byte) error {
	l.wmu.Lock()
	defer l.wmu.Unlock()
	var lead []byte
	if first := firstRecordLen(a, b); first > 0 && first < len(a)+len(b) &&
		len(l.prefix)+frameHead+first+frameHead+4 <= maxPlain {
		rec := make([]byte, 0, first)
		k := minInt(first, len(a))
		rec = append(append(rec, a[:k]...), b[:first-k]...)
		a, b = a[k:], b[first-k:]
		lead = appendFrame(make([]byte, 0, frameHead+first+frameHead+4), frData, rec)
		l.event("rawlead")
	}
	// Cork the socket between the RAW frame and its data, so that the announcement does not travel in a
	// packet of its own.
	setCork(l.sock, true)
	err := l.writeRawHeaderAfter(lead, len(a)+len(b))
	if err == nil {
		switch {
		case len(a) == 0:
			_, err = l.sock.Write(b)
		case len(b) == 0:
			_, err = l.sock.Write(a)
		default:
			bufs := net.Buffers{a, b} // one writev
			_, err = bufs.WriteTo(l.sock)
		}
	}
	setCork(l.sock, false)
	if err == nil {
		l.event("raw")
	}
	return err
}

// jitter returns d scaled by a random factor in [low, 1].
func jitter(d time.Duration, low float64) time.Duration {
	return time.Duration(float64(d) * (low + (1-low)*mrand.Float64()))
}

func (l *lane) settingsText(extra string) []byte {
	raw := "0"
	if l.canRaw {
		raw = "1"
	}
	return []byte("v=2\nraw=" + raw + extra)
}
