package miu

import "sync/atomic"

// streamState is what the two directions of one stream share.
type streamState struct {
	// tls13 is set once the inner handshake's ServerHello has selected TLS 1.3.
	tls13 atomic.Bool
}

// recScan follows the inner TLS record boundaries along one direction of a stream. It notes whether the
// ServerHello selects TLS 1.3 and, once that is known, reports the first application_data record header
// seen on a record boundary: from there on the direction may use raw segments. The condition is the one
// XTLS-Vision uses to switch to direct copy, but boundaries are tracked over the byte stream, so no
// single read has to line up with a record.
//
// A sending side keeps following the boundaries in the raw phase (follow): a raw segment may only hold
// whole inner records. The bytes on the wire are outer records and raw bytes in turn, and the raw bytes
// are inner records; a segment that stopped inside an inner record would put the next outer record in
// the middle of it, and the wire would no longer read as a sequence of TLS records.
type recScan struct {
	st   *streamState
	hdr  []byte
	need int
	sh   []byte
	inSH bool
	seen int
	dead bool
	// ready latches the result: once true, feed keeps returning true.
	ready bool
	// follow keeps the boundaries tracked after ready (the sending side of a direction).
	follow bool
	// lost: after ready the bytes stopped parsing as TLS records, so boundaries are no longer known.
	lost bool
}

// feed consumes the next bytes of the direction and reports whether raw segments may start after them.
func (s *recScan) feed(b []byte) bool {
	if s.ready && !s.follow {
		return true
	}
	if s.dead {
		return false
	}
	if !s.ready {
		if s.seen += len(b); s.seen > sniffLimit {
			s.dead = true
			return false
		}
	}
	s.walk(b)
	return s.ready
}

// walk advances over b and returns the offsets in b just past the first and the last inner record that
// ended in it (-1 when none did).
func (s *recScan) walk(b []byte) (first, last int) {
	first, last = -1, -1
	off := 0
	ended := func() {
		if first < 0 {
			first = off
		}
		last = off
	}
	for off < len(b) && !s.dead && !s.lost {
		if s.need > 0 {
			k := minInt(s.need, len(b)-off)
			if s.inSH {
				s.sh = append(s.sh, b[off:off+k]...)
			}
			s.need -= k
			off += k
			if s.need == 0 {
				if s.inSH {
					s.inSH = false
					if isTLS13ServerHello(s.sh) {
						s.st.tls13.Store(true)
					}
					s.sh = nil
				}
				ended()
			}
			continue
		}
		k := minInt(5-len(s.hdr), len(b)-off)
		s.hdr = append(s.hdr, b[off:off+k]...)
		off += k
		if len(s.hdr) < 5 {
			break
		}
		typ := s.hdr[0]
		if s.hdr[1] != 3 || typ < 0x14 || typ > 0x17 {
			if s.ready {
				s.lost = true
			} else {
				s.dead = true // not TLS
			}
			break
		}
		if typ == 0x17 && s.st.tls13.Load() {
			s.ready = true
		}
		s.need = int(s.hdr[3])<<8 | int(s.hdr[4])
		s.inSH = typ == 0x16 && !s.ready && !s.st.tls13.Load()
		s.hdr = s.hdr[:0]
		if s.need == 0 {
			ended()
		}
	}
	return first, last
}

// atBoundary reports whether the bytes walked so far end on an inner record boundary.
func (s *recScan) atBoundary() bool { return s.need == 0 && len(s.hdr) == 0 }

// remaining is how many more bytes complete what the walk is in the middle of: the current record, or
// the record header when that is not complete yet (the record itself then needs more).
func (s *recScan) remaining() int {
	if s.need > 0 {
		return s.need
	}
	return 5 - len(s.hdr)
}

// clone returns a copy to probe bytes with, without moving s.
func (s *recScan) clone() recScan {
	c := *s
	c.hdr = append([]byte(nil), s.hdr...)
	c.sh = append([]byte(nil), s.sh...)
	return c
}

// isTLS13ServerHello reports whether b is a ServerHello handshake message whose supported_versions
// extension selects 0x0304.
func isTLS13ServerHello(b []byte) bool {
	if len(b) < 4+2+32+1 || b[0] != 2 {
		return false
	}
	p := b[4+2+32:]
	sid := int(p[0])
	if len(p) < 1+sid+3+2 {
		return false
	}
	p = p[1+sid+3:]
	n := int(p[0])<<8 | int(p[1])
	if p = p[2:]; n < len(p) {
		p = p[:n]
	}
	for len(p) >= 4 {
		typ := int(p[0])<<8 | int(p[1])
		l := int(p[2])<<8 | int(p[3])
		if len(p) < 4+l {
			return false
		}
		if typ == 0x002b && l == 2 && p[4] == 3 && p[5] == 4 {
			return true
		}
		p = p[4+l:]
	}
	return false
}
