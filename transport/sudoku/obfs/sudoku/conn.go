package sudoku

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// decodeWindow bounds how many wire bytes decode compacts at a time.
const decodeWindow = 256

type Conn struct {
	net.Conn
	table      *Table
	reader     *wireReader
	recorder   *bytes.Buffer
	recording  atomic.Bool
	recordLock sync.Mutex

	hintBuf   [3]uint8 // hint indexes of a group still being read
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

// GetBufferedAndRecorded returns every wire byte read so far that has not been
// stopped from recording, plus bytes buffered but not yet decoded.
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
	pending := sc.reader.pending()
	if len(pending) == 0 {
		return recorded
	}
	full := make([]byte, len(recorded)+len(pending))
	copy(full, recorded)
	copy(full[len(recorded):], pending)
	return full
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
	if sc == nil || sc.Conn == nil || sc.table == nil || sc.table.layout == nil {
		return 0, io.ErrClosedPipe
	}
	if sc.reader == nil {
		// Write-only codecs never pay for a read buffer.
		sc.reader = &wireReader{src: sc.Conn}
	}

	outN := 0
	for {
		chunk, rErr := sc.reader.peek()
		if len(chunk) > 0 {
			var consumed int
			outN, consumed, rErr = sc.decode(p, chunk)
			if sc.recording.Load() {
				sc.recordLock.Lock()
				if sc.recording.Load() && sc.recorder != nil {
					sc.recorder.Write(chunk[:consumed])
				}
				sc.recordLock.Unlock()
			}
			sc.reader.discard(consumed)
		}
		if rErr != nil {
			return 0, rErr
		}
		if outN > 0 {
			return outN, nil
		}
	}
}

// decode writes only as much plaintext as fits in p, so the wire bytes it
// consumed can be dropped and the rest stay in the reader. It consumes whole
// windows of wire bytes, keeping the hints of an unfinished group in hintBuf,
// but never more than can complete into the space left in p. Compacting a
// window through hintIdx with a branchless store skips padding without a
// per-byte branch.
func (sc *Conn) decode(p, chunk []byte) (outN, consumed int, err error) {
	table := sc.table
	hintIdx := &table.layout.hintIdx
	var hints [512]uint8

	for consumed < len(chunk) && outN < len(p) {
		window := minInt(minInt(len(chunk)-consumed, decodeWindow), 4*(len(p)-outN)+3-sc.hintCount)
		k := copy(hints[:], sc.hintBuf[:sc.hintCount])
		for _, b := range chunk[consumed : consumed+window] {
			idx := hintIdx[b]
			hints[k&511] = idx
			k += int(idx>>7) ^ 1
		}
		consumed += window

		groups := k / 4
		for i := 0; i < groups; i++ {
			h := (*[4]uint8)(hints[4*i:])
			val, ok := table.decodeHints(h[0], h[1], h[2], h[3])
			if !ok {
				sc.hintCount = 0
				return outN, consumed, ErrInvalidSudokuMapMiss
			}
			p[outN] = val
			outN++
		}
		sc.hintCount = copy(sc.hintBuf[:], hints[4*groups:k])
	}
	return outN, consumed, nil
}
