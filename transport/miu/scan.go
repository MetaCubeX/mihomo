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
}

// feed consumes the next bytes of the direction and reports whether raw segments may start after them.
func (s *recScan) feed(b []byte) bool {
	if s.ready {
		return true
	}
	if s.dead {
		return false
	}
	if s.seen += len(b); s.seen > sniffLimit {
		s.dead = true
		return false
	}
	for len(b) > 0 {
		if s.need > 0 {
			k := minInt(s.need, len(b))
			if s.inSH {
				s.sh = append(s.sh, b[:k]...)
			}
			s.need -= k
			b = b[k:]
			if s.need == 0 && s.inSH {
				s.inSH = false
				if isTLS13ServerHello(s.sh) {
					s.st.tls13.Store(true)
				}
				s.sh = nil
			}
			continue
		}
		k := minInt(5-len(s.hdr), len(b))
		s.hdr = append(s.hdr, b[:k]...)
		b = b[k:]
		if len(s.hdr) < 5 {
			break
		}
		typ := s.hdr[0]
		if s.hdr[1] != 3 || typ < 0x14 || typ > 0x17 {
			s.dead = true // not TLS
			return false
		}
		if typ == 0x17 && s.st.tls13.Load() {
			s.ready = true
			return true
		}
		s.need = int(s.hdr[3])<<8 | int(s.hdr[4])
		s.inSH = typ == 0x16 && !s.st.tls13.Load()
		s.hdr = s.hdr[:0]
	}
	return false
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
