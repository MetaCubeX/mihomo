package xhttp

import (
	"errors"
	"io"
	"sync"
)

type Packet struct {
	Seq     uint64
	Payload []byte // UploadQueue will hold Payload, so never reuse it after UploadQueue.Push
	Reader  io.ReadCloser
}

type UploadQueue struct {
	mu         sync.Mutex
	condPushed sync.Cond
	condPopped sync.Cond
	packets    map[uint64][]byte
	nextSeq    uint64
	buf        []byte
	closed     bool
	maxPackets int
	reader     io.ReadCloser
}

func NewUploadQueue(maxPackets int) *UploadQueue {
	q := &UploadQueue{
		packets:    make(map[uint64][]byte, maxPackets),
		maxPackets: maxPackets,
	}
	q.condPushed = sync.Cond{L: &q.mu}
	q.condPopped = sync.Cond{L: &q.mu}
	return q
}

func (q *UploadQueue) Push(p Packet) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return io.ErrClosedPipe
	}

	if q.reader != nil {
		return errors.New("uploadQueue.reader already exists")
	}

	if p.Reader != nil {
		q.reader = p.Reader
		q.condPushed.Broadcast()
		return nil
	}

	for len(q.packets) > q.maxPackets {
		q.condPopped.Wait() // wait for the reader to read the packets
		if q.closed {
			return io.ErrClosedPipe
		}
	}

	q.packets[p.Seq] = p.Payload
	q.condPushed.Broadcast()
	return nil
}

func (q *UploadQueue) Read(b []byte) (int, error) {
	q.mu.Lock()

	for {
		if len(q.buf) > 0 {
			n := copy(b, q.buf)
			q.buf = q.buf[n:]
			q.mu.Unlock()
			return n, nil
		}

		if payload, ok := q.packets[q.nextSeq]; ok {
			delete(q.packets, q.nextSeq)
			q.nextSeq++
			q.buf = payload
			q.condPopped.Broadcast()
			continue
		}

		if reader := q.reader; reader != nil {
			q.mu.Unlock() // unlock before calling q.reader.Read
			return reader.Read(b)
		}

		if q.closed {
			q.mu.Unlock()
			return 0, io.EOF
		}

		if len(q.packets) > q.maxPackets {
			q.mu.Unlock()
			// the "reassembly buffer" is too large, and we want to constrain memory usage somehow.
			// let's tear down the connection and hope the application retries.
			return 0, errors.New("packet queue is too large")
		}

		q.condPushed.Wait()
	}
}

func (q *UploadQueue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()

	var err error
	if q.reader != nil {
		err = q.reader.Close()
	}
	q.closed = true
	q.condPushed.Broadcast()
	q.condPopped.Broadcast()
	return err
}
