package sudoku

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

const IOBufferSize = 32 * 1024

const minDecodeReadSize = 64

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

	hintBuf   [4]byte
	hintCount int
	writeMu   sync.Mutex
	writeBuf  []byte

	rng              *sudokuRand
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
	if sc == nil {
		return
	}
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
	if sc.reader == nil {
		return recorded
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
	if sc == nil || sc.Conn == nil || sc.table == nil || sc.table.layout == nil || sc.rng == nil {
		return 0, io.ErrClosedPipe
	}

	sc.writeMu.Lock()
	defer sc.writeMu.Unlock()

	sc.writeBuf, n, err = writeSudokuPayload(sc.Conn, sc.writeBuf, sc.table, sc.rng, sc.paddingThreshold, p)
	return n, err
}

func (sc *Conn) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if sc == nil || sc.Conn == nil || sc.reader == nil || sc.table == nil || sc.table.layout == nil {
		return 0, io.ErrClosedPipe
	}
	for {
		chunk, peekErr := peekBufferedChunk(sc.reader)
		if len(chunk) > 0 {
			n, consumed, decErr := sc.decode(p, chunk)
			_, _ = sc.reader.Discard(consumed)
			if sc.recording.Load() && consumed > 0 {
				sc.recordLock.Lock()
				if sc.recording.Load() && sc.recorder != nil {
					_, _ = sc.recorder.Write(chunk[:consumed])
				}
				sc.recordLock.Unlock()
			}
			if decErr != nil {
				return n, decErr
			}
			if n > 0 {
				return n, nil
			}
		}
		if peekErr != nil {
			return 0, peekErr
		}
	}
}

func sudokuReadSize(decodedRemaining, maxRaw int) int {
	if maxRaw <= minDecodeReadSize || decodedRemaining <= 0 {
		return maxRaw
	}
	if decodedRemaining > (maxRaw-minDecodeReadSize)/9 {
		return maxRaw
	}

	return decodedRemaining*9 + minDecodeReadSize
}

func readRawLimited(conn net.Conn, reader *bufio.Reader, dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	if reader != nil && reader.Buffered() > 0 {
		return reader.Read(dst)
	}
	if conn == nil {
		return 0, io.ErrClosedPipe
	}
	return conn.Read(dst)
}
