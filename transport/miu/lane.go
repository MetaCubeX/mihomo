package miu

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

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

	wmu    sync.Mutex
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
		padding.UpdatePaddingScheme(payload, &l.scheme)
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

func (l *lane) write(p []byte) error {
	_, err := l.conn.Write(p)
	return err
}

func (l *lane) writeFrame(typ byte, payload []byte) error {
	l.wmu.Lock()
	defer l.wmu.Unlock()
	return l.write(appendFrame(make([]byte, 0, frameHead+len(payload)), typ, payload))
}

// writeUnshaped writes already encoded frames as they are.
func (l *lane) writeUnshaped(p []byte) error {
	l.wmu.Lock()
	defer l.wmu.Unlock()
	return l.write(p)
}

// writePacket sends one "packet" (a few encoded frames). While pkt is below the scheme's stop, the packet
// is cut into TLS records of the prescribed lengths, the last one filled up with a PAD frame; otherwise it
// goes out in one write. A cut may fall inside a frame: the peer parses frames from the byte stream.
func (l *lane) writePacket(pkt uint32, p []byte) error {
	l.wmu.Lock()
	defer l.wmu.Unlock()
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

// writeRawHeader writes a record holding nothing but a RAW frame: n raw bytes follow. Caller holds wmu.
func (l *lane) writeRawHeader(n int) error {
	var hdr [frameHead + 4]byte
	hdr[0], hdr[2] = frRaw, 4
	binary.BigEndian.PutUint32(hdr[frameHead:], uint32(n))
	return l.write(hdr[:])
}

// writeRaw sends p as raw segments: a record with only a RAW frame, then the bytes straight to the socket.
func (l *lane) writeRaw(p []byte) error {
	l.wmu.Lock()
	defer l.wmu.Unlock()
	for len(p) > 0 {
		seg := p[:minInt(len(p), maxSeg)]
		p = p[len(seg):]
		// Cork the socket between the RAW frame and its data, so that the record of a few dozen bytes
		// does not travel in a packet of its own.
		setCork(l.sock, true)
		err := l.writeRawHeader(len(seg))
		if err == nil {
			_, err = l.sock.Write(seg)
		}
		setCork(l.sock, false)
		if err != nil {
			return err
		}
		l.event("raw")
	}
	return nil
}

func (l *lane) settingsText(extra string) []byte {
	raw := "0"
	if l.canRaw {
		raw = "1"
	}
	return []byte("v=2\nraw=" + raw + extra)
}
