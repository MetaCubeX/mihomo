package sudoku

import (
	"io"
	"net"
	"sync"
)

// DownlinkWriter encodes payload bytes with the selected downlink codec.
type DownlinkWriter struct {
	dataWriter io.Writer
	writeMu    sync.Mutex
}

func NewDownlinkWriter(raw io.Writer, table *Table, pMin, pMax int) *DownlinkWriter {
	localRng := newSeededRand()
	return newDownlinkWriter(newSudokuDataWriter(raw, table, localRng, pMin, pMax))
}

func NewPackedDownlinkWriter(raw net.Conn, table *Table, pMin, pMax int) (*PackedConn, *DownlinkWriter) {
	packed := NewPackedConn(raw, table, pMin, pMax)
	return packed, newDownlinkWriter(packed)
}

func NewServerDownlinkWriter(raw net.Conn, table *Table, pMin, pMax int, pure bool) (io.Writer, []func() error) {
	if pure {
		return NewDownlinkWriter(raw, table, pMin, pMax), nil
	}

	packed, writer := NewPackedDownlinkWriter(raw, table, pMin, pMax)
	return writer, []func() error{packed.Flush}
}

func newDownlinkWriter(dataWriter io.Writer) *DownlinkWriter {
	return &DownlinkWriter{dataWriter: dataWriter}
}

func (w *DownlinkWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if w == nil || w.dataWriter == nil {
		return 0, io.ErrClosedPipe
	}

	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	return w.dataWriter.Write(p)
}

type sudokuDataWriter struct {
	writer           io.Writer
	table            *Table
	rng              *sudokuRand
	paddingThreshold uint64
	writeBuf         []byte
}

func newSudokuDataWriter(writer io.Writer, table *Table, rng *sudokuRand, pMin, pMax int) *sudokuDataWriter {
	return &sudokuDataWriter{
		writer:           writer,
		table:            table,
		rng:              rng,
		paddingThreshold: pickPaddingThreshold(rng, pMin, pMax),
		writeBuf:         make([]byte, 0, 4096),
	}
}

func (w *sudokuDataWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if w == nil || w.writer == nil {
		return 0, io.ErrClosedPipe
	}
	if w.table == nil || w.table.layout == nil || w.rng == nil {
		return 0, io.ErrClosedPipe
	}

	w.writeBuf = encodeSudokuPayload(w.writeBuf[:0], w.table, w.rng, w.paddingThreshold, p)
	return len(p), writeFull(w.writer, w.writeBuf)
}
