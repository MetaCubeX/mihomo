package openvpn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	fragmentWhole       = 0
	fragmentPartial     = 1
	fragmentLast        = 2
	fragmentMaxParts    = 32
	fragmentTimeout     = 30 * time.Second
	fragmentMaxPacket   = 1<<16 - 1
	fragmentMaxBuffered = 4 << 20
)

type fragmentBuffer struct {
	maxSize int
	lastID  int
	parts   map[int][]byte
	bytes   int
	updated time.Time
}

type Fragmenter struct {
	mu            sync.Mutex
	outSequence   int
	incoming      map[int]*fragmentBuffer
	incomingBytes int
}

func NewFragmenter() *Fragmenter {
	return &Fragmenter{incoming: make(map[int]*fragmentBuffer)}
}

func (f *Fragmenter) Encode(payload []byte, size int) ([][]byte, error) {
	size &= ^3
	if size <= 0 {
		return nil, errors.New("fragment payload size too small")
	}
	if len(payload) <= size {
		return [][]byte{fragmentFrame(payload, fragmentWhole, 0, 0, 0)}, nil
	}
	f.mu.Lock()
	seq := f.outSequence
	f.outSequence = (f.outSequence + 1) & 0xff
	f.mu.Unlock()
	out := make([][]byte, 0, (len(payload)+size-1)/size)
	for off, id := 0, 0; off < len(payload); id++ {
		if id >= fragmentMaxParts {
			return nil, errors.New("too many OpenVPN fragments")
		}
		n := size
		if len(payload)-off < n {
			n = len(payload) - off
		}
		kind, max := fragmentPartial, 0
		if off+n == len(payload) {
			kind, max = fragmentLast, size>>2
		}
		out = append(out, fragmentFrame(payload[off:off+n], kind, seq, id, max))
		off += n
	}
	return out, nil
}

func fragmentFrame(payload []byte, kind, seq, id, max int) []byte {
	flags := uint32(kind&3) | uint32(seq&0xff)<<2 | uint32(id&0x1f)<<10
	if kind == fragmentLast {
		flags |= uint32(max&0x3fff) << 15
	}
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out[:4], flags)
	copy(out[4:], payload)
	return out
}

func (f *Fragmenter) Decode(frame []byte) ([]byte, bool, error) {
	if len(frame) < 4 {
		return nil, false, errors.New("fragment header missing")
	}
	flags := binary.BigEndian.Uint32(frame[:4])
	kind := int(flags & 3)
	payload := frame[4:]
	if kind == fragmentWhole {
		if flags&^uint32(3) != 0 {
			return nil, false, errors.New("spurious fragment flags")
		}
		return append([]byte(nil), payload...), true, nil
	}
	if kind != fragmentPartial && kind != fragmentLast {
		return nil, false, errors.New("unknown fragment type")
	}
	seq := int((flags >> 2) & 0xff)
	id := int((flags >> 10) & 0x1f)
	maxSize := int((flags>>15)&0x3fff) << 2
	return f.store(seq, id, maxSize, kind == fragmentLast, payload)
}

func (f *Fragmenter) store(seq, id, maxSize int, last bool, payload []byte) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	for key, buffer := range f.incoming {
		if now.Sub(buffer.updated) >= fragmentTimeout {
			f.incomingBytes -= buffer.bytes
			delete(f.incoming, key)
		}
	}
	if len(payload) > fragmentMaxPacket {
		return nil, false, errors.New("fragment too large")
	}
	size := len(payload)
	if maxSize > 0 {
		size = maxSize
	}
	buffer := f.incoming[seq]
	if buffer != nil && buffer.maxSize != size {
		f.incomingBytes -= buffer.bytes
		delete(f.incoming, seq)
		buffer = nil
	}
	if buffer == nil {
		buffer = &fragmentBuffer{maxSize: size, lastID: -1, parts: make(map[int][]byte), updated: now}
		f.incoming[seq] = buffer
	}
	previous := len(buffer.parts[id])
	additional := len(payload) - previous
	if buffer.bytes+additional > fragmentMaxPacket || f.incomingBytes+additional > fragmentMaxBuffered {
		return nil, false, errors.New("fragment reassembly limit exceeded")
	}
	buffer.parts[id] = append([]byte(nil), payload...)
	buffer.bytes += additional
	buffer.updated = now
	f.incomingBytes += additional
	if last {
		buffer.lastID = id
	}
	if buffer.lastID < 0 {
		return nil, false, nil
	}
	total := 0
	for part := 0; part <= buffer.lastID; part++ {
		p, ok := buffer.parts[part]
		if !ok {
			return nil, false, nil
		}
		total += len(p)
	}
	if total > fragmentMaxPacket {
		return nil, false, fmt.Errorf("reassembled packet too large: %d", total)
	}
	out := make([]byte, 0, total)
	for part := 0; part <= buffer.lastID; part++ {
		out = append(out, buffer.parts[part]...)
	}
	f.incomingBytes -= buffer.bytes
	delete(f.incoming, seq)
	return out, true, nil
}
