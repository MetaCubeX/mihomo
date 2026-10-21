package sudoku

import (
	"io"
	"net"
	"sync"
)

// NewServerDownlinkWriter returns the server-to-client writer for a connection
// whose uplink is already wrapped. The packed codec buffers residual bits, so
// its Flush is returned as a closer to run before the connection is closed.
func NewServerDownlinkWriter(raw net.Conn, table *Table, pMin, pMax int, pure bool) (io.Writer, []func() error) {
	if pure {
		return newPureWriter(raw, table, newSeededRand(), pMin, pMax), nil
	}

	packed := NewPackedConn(raw, table, pMin, pMax)
	return writerOnly{packed}, []func() error{packed.Flush}
}

// writerOnly hides every method but Write, so wrapping it in a directional
// conn does not half-close the shared socket twice.
type writerOnly struct{ io.Writer }

// pureWriter is the write half of Conn, safe for concurrent callers.
type pureWriter struct {
	mu               sync.Mutex
	writer           io.Writer
	table            *Table
	rng              *sudokuRand
	paddingThreshold uint64
	writeBuf         []byte
}

func newPureWriter(writer io.Writer, table *Table, rng *sudokuRand, pMin, pMax int) *pureWriter {
	return &pureWriter{
		writer:           writer,
		table:            table,
		rng:              rng,
		paddingThreshold: pickPaddingThreshold(rng, pMin, pMax),
	}
}

func (w *pureWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if w == nil || w.writer == nil || w.table == nil || w.table.layout == nil || w.rng == nil {
		return 0, io.ErrClosedPipe
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	var n int
	var err error
	w.writeBuf, n, err = writeSudokuPayload(w.writer, w.writeBuf, w.table, w.rng, w.paddingThreshold, p)
	return n, err
}
