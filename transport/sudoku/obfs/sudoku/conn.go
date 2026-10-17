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

type Conn struct {
	net.Conn
	table      *Table
	reader     *bufio.Reader
	recorder   *bytes.Buffer
	recording  atomic.Bool
	recordLock sync.Mutex

	rawBuf      []byte
	pendingData pendingBuffer
	hintBuf     [4]uint8 // hint indexes of a group still being read
	hintCount   int
	writeMu     sync.Mutex
	writeBuf    []byte

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

	sc.writeBuf = encodeSudokuPayload(sc.writeBuf[:0], sc.table, sc.rng, sc.paddingThreshold, p)
	if _, err := sc.Conn.Write(sc.writeBuf); err != nil {
		return len(p), err
	}
	return len(p), nil
}

func (sc *Conn) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if sc == nil || sc.Conn == nil || sc.reader == nil || len(sc.rawBuf) == 0 || sc.table == nil || sc.table.layout == nil {
		return 0, io.ErrClosedPipe
	}
	if n, ok := drainPending(p, &sc.pendingData); ok {
		return n, nil
	}

	outN := 0
	for {
		nr, rErr := readRawLimited(sc.Conn, sc.reader, sc.rawBuf[:sudokuReadSize(len(p)-outN, len(sc.rawBuf))])
		if nr > 0 {
			chunk := sc.rawBuf[:nr]
			if sc.recording.Load() {
				sc.recordLock.Lock()
				if sc.recording.Load() && sc.recorder != nil {
					sc.recorder.Write(chunk)
				}
				sc.recordLock.Unlock()
			}

			table := sc.table
			hintIdx := &table.layout.hintIdx
			for i := 0; i < len(chunk); {
				if sc.hintCount == 0 && outN < len(p) && i+3 < len(chunk) {
					h0, h1, h2, h3 := hintIdx[chunk[i]], hintIdx[chunk[i+1]], hintIdx[chunk[i+2]], hintIdx[chunk[i+3]]
					if (h0|h1|h2|h3)&notHint == 0 {
						val, ok := table.decodeHints(h0, h1, h2, h3)
						if !ok {
							return 0, ErrInvalidSudokuMapMiss
						}
						p[outN] = val
						outN++
						i += 4
						continue
					}
				}

				idx := hintIdx[chunk[i]]
				i++
				if idx&notHint != 0 {
					continue
				}

				sc.hintBuf[sc.hintCount] = idx
				sc.hintCount++
				if sc.hintCount != len(sc.hintBuf) {
					continue
				}

				val, ok := table.decodeHints(sc.hintBuf[0], sc.hintBuf[1], sc.hintBuf[2], sc.hintBuf[3])
				if !ok {
					return 0, ErrInvalidSudokuMapMiss
				}
				outN = appendDecodedByte(p, outN, &sc.pendingData, val)
				sc.hintCount = 0
			}
		}

		if rErr != nil {
			if outN > 0 {
				return outN, nil
			}
			if n, ok := drainPending(p, &sc.pendingData); ok {
				return n, nil
			}
			return 0, rErr
		}
		if outN > 0 {
			return outN, nil
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
