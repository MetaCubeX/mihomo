package sudoku

import (
	"io"
	"math"

	"github.com/metacubex/mihomo/common/pool"
)

const (
	// maxEncodedWriteSize bounds one Write to the underlying connection and the
	// encode buffer, matching readBufferSize.
	maxEncodedWriteSize = 32 * 1024
	// retainedWriteBytes is the encode buffer a connection keeps between writes.
	// Larger encodes borrow a pooled buffer for the duration of one Write.
	retainedWriteBytes = 2048
)

// minInt exists because the module still targets Go 1.20, which has no min.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// writeSudokuPayload encodes p and writes it to w, keeping the encode buffer
// bounded however large p is. It fills the remaining space with complete
// payload bytes, then sends that buffer. The padding slot that closes a Write
// belongs to the whole Write, never to an internal batch.
func writeSudokuPayload(w io.Writer, buf []byte, table *Table, rng *sudokuRand, threshold uint64, p []byte) ([]byte, int, error) {
	expansion := maxPaddedExpansion
	if threshold == 0 {
		expansion = 4
	}
	buf = growWriteBuf(buf, minInt(minInt(len(p), maxEncodedWriteSize)*expansion+encodeSlack, maxEncodedWriteSize))
	out := buf[:0]
	total, buffered := 0, 0
	for len(p) > 0 {
		n := minInt(len(p), (cap(out)-len(out)-encodeSlack)/expansion)
		if n == 0 {
			if _, err := w.Write(out); err != nil {
				return releaseWriteBuf(out), total, err
			}
			total += buffered
			buffered = 0
			out = out[:0]
			continue
		}
		out = appendSudokuPayload(out, table, rng, threshold, p[:n])
		buffered += n
		p = p[n:]
	}

	if threshold != 0 {
		draw := rng.Uint64()
		if draw&math.MaxUint32 < threshold {
			pad := table.PaddingPool
			out = append(out, pad[(draw>>32)*uint64(len(pad))>>32])
		}
	}
	if _, err := w.Write(out); err != nil {
		return releaseWriteBuf(out), total, err
	}
	return releaseWriteBuf(out), total + buffered, nil
}

// growWriteBuf returns an empty buffer with room for need bytes, borrowed from
// the pool when need exceeds what a connection may retain.
func growWriteBuf(buf []byte, need int) []byte {
	if cap(buf) >= need {
		return buf[:0]
	}
	if need <= retainedWriteBytes {
		return make([]byte, 0, need)
	}
	return pool.Get(maxEncodedWriteSize)[:0]
}

// releaseWriteBuf keeps a small buffer for the next Write and returns a pooled
// one.
func releaseWriteBuf(buf []byte) []byte {
	if cap(buf) <= retainedWriteBytes {
		return buf[:0]
	}
	pool.Put(buf)
	return nil
}
