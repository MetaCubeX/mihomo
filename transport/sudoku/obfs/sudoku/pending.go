package sudoku

type pendingBuffer struct {
	data []byte
	off  int
}

func newPendingBuffer(capacity int) pendingBuffer {
	return pendingBuffer{data: make([]byte, 0, capacity)}
}

func (p *pendingBuffer) available() int {
	if p == nil {
		return 0
	}
	return len(p.data) - p.off
}

func (p *pendingBuffer) reset() {
	if p == nil {
		return
	}
	p.data = p.data[:0]
	p.off = 0
}

func (p *pendingBuffer) ensureAppendCapacity(extra int) {
	if p == nil || extra <= 0 || p.off == 0 {
		return
	}
	if cap(p.data)-len(p.data) >= extra {
		return
	}

	unread := len(p.data) - p.off
	copy(p.data[:unread], p.data[p.off:])
	p.data = p.data[:unread]
	p.off = 0
}

func (p *pendingBuffer) appendByte(b byte) {
	p.ensureAppendCapacity(1)
	p.data = append(p.data, b)
}

func drainPending(dst []byte, pending *pendingBuffer) (int, bool) {
	if pending == nil || pending.available() == 0 {
		return 0, false
	}

	n := copy(dst, pending.data[pending.off:])
	pending.off += n
	if pending.off == len(pending.data) {
		pending.reset()
	}
	return n, true
}
