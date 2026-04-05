package sudoku

import (
	"bufio"
	"bytes"
	"net"
	"sync"
	"sync/atomic"
)

const IOBufferSize = 32 * 1024

var perm4 = [24][4]byte{
	{0, 1, 2, 3},
	{0, 1, 3, 2},
	{0, 2, 1, 3},
	{0, 2, 3, 1},
	{0, 3, 1, 2},
	{0, 3, 2, 1},
	{1, 0, 2, 3},
	{1, 0, 3, 2},
	{1, 2, 0, 3},
	{1, 2, 3, 0},
	{1, 3, 0, 2},
	{1, 3, 2, 0},
	{2, 0, 1, 3},
	{2, 0, 3, 1},
	{2, 1, 0, 3},
	{2, 1, 3, 0},
	{2, 3, 0, 1},
	{2, 3, 1, 0},
	{3, 0, 1, 2},
	{3, 0, 2, 1},
	{3, 1, 0, 2},
	{3, 1, 2, 0},
	{3, 2, 0, 1},
	{3, 2, 1, 0},
}

type Conn struct {
	net.Conn
	table      *Table
	reader     *bufio.Reader
	recorder   *bytes.Buffer
	recording  atomic.Bool
	recordLock sync.Mutex

	rawBuf      []byte
	pendingData pendingBuffer
	hintBuf     [4]byte
	hintCount   int
	writeMu     sync.Mutex
	writeBuf    []byte

	rng              randomSource
	paddingThreshold uint64
}

func (sc *Conn) CloseWrite() error {
	if sc == nil || sc.Conn == nil {
		return nil
	}
	if cw, ok := sc.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (sc *Conn) CloseRead() error {
	if sc == nil || sc.Conn == nil {
		return nil
	}
	if cr, ok := sc.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

func NewConn(c net.Conn, table *Table, pMin, pMax int, record bool) *Conn {
	localRng := newSeededRand()

	sc := &Conn{
		Conn:             c,
		table:            table,
		reader:           bufio.NewReaderSize(c, IOBufferSize),
		rawBuf:           make([]byte, IOBufferSize),
		pendingData:      newPendingBuffer(4096),
		writeBuf:         make([]byte, 0, 4096),
		rng:              localRng,
		paddingThreshold: pickPaddingThreshold(localRng, pMin, pMax),
	}
	if record {
		sc.recorder = new(bytes.Buffer)
		sc.recording.Store(true)
	}
	return sc
}

func (sc *Conn) StopRecording() {
	sc.recordLock.Lock()
	sc.recording.Store(false)
	sc.recorder = nil
	sc.recordLock.Unlock()
}

func (sc *Conn) GetBufferedAndRecorded() []byte {
	if sc == nil {
		return nil
	}

	sc.recordLock.Lock()
	defer sc.recordLock.Unlock()

	var recorded []byte
	if sc.recorder != nil {
		recorded = sc.recorder.Bytes()
	}

	buffered := sc.reader.Buffered()
	if buffered > 0 {
		peeked, _ := sc.reader.Peek(buffered)
		full := make([]byte, len(recorded)+len(peeked))
		copy(full, recorded)
		copy(full[len(recorded):], peeked)
		return full
	}
	return recorded
}

func (sc *Conn) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	sc.writeMu.Lock()
	defer sc.writeMu.Unlock()

	sc.writeBuf = encodeSudokuPayload(sc.writeBuf[:0], sc.table, sc.rng, sc.paddingThreshold, p)
	return len(p), writeFull(sc.Conn, sc.writeBuf)
}

func (sc *Conn) Read(p []byte) (n int, err error) {
	if n, ok := drainPending(p, &sc.pendingData); ok {
		return n, nil
	}

	for {
		if sc.pendingData.available() > 0 {
			break
		}

		nr, rErr := sc.reader.Read(sc.rawBuf)
		if nr > 0 {
			chunk := sc.rawBuf[:nr]
			if sc.recording.Load() {
				sc.recordLock.Lock()
				if sc.recording.Load() && sc.recorder != nil {
					sc.recorder.Write(chunk)
				}
				sc.recordLock.Unlock()
			}

			layout := sc.table.layout
			for _, b := range chunk {
				if !layout.hintTable[b] {
					continue
				}

				sc.hintBuf[sc.hintCount] = b
				sc.hintCount++
				if sc.hintCount == len(sc.hintBuf) {
					key := packHintsToKey(sc.hintBuf)
					val, ok := sc.table.DecodeMap[key]
					if !ok {
						return 0, ErrInvalidSudokuMapMiss
					}
					sc.pendingData.appendByte(val)
					sc.hintCount = 0
				}
			}
		}

		if rErr != nil {
			return 0, rErr
		}
		if sc.pendingData.available() > 0 {
			break
		}
	}

	n, _ = drainPending(p, &sc.pendingData)
	return n, nil
}
