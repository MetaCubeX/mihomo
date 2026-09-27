package sudoku

import (
	"io"

	"github.com/metacubex/mihomo/transport/sudoku/connutil"
)

const maxEncodedWriteSize = 32 * 1024

func writeSudokuPayload(w io.Writer, buf []byte, table *Table, rng *sudokuRand, threshold uint64, p []byte) ([]byte, int, error) {
	maxExpansion := 9
	if threshold == 0 {
		maxExpansion = 4
	}
	limit := len(p)
	if limit > maxEncodedWriteSize {
		limit = maxEncodedWriteSize
	}
	needed := limit*maxExpansion + 1
	if needed > maxEncodedWriteSize {
		needed = maxEncodedWriteSize
	}
	if cap(buf) < needed {
		buf = make([]byte, 0, needed)
	}
	out := buf[:0]
	total, buffered := 0, 0
	for len(p) > 0 {
		n := (cap(out) - len(out) - 1) / maxExpansion
		if n > len(p) {
			n = len(p)
		}
		if n == 0 {
			if err := writeEncoded(w, out); err != nil {
				return out[:0], total, err
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
	if threshold >= probOne || (threshold != 0 && uint64(rng.Uint32()) < threshold) {
		out = append(out, table.PaddingPool[rng.Intn(len(table.PaddingPool))])
	}
	if err := writeEncoded(w, out); err != nil {
		return out[:0], total, err
	}
	return out[:0], total + buffered, nil
}

func writeEncoded(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n := len(p)
		if n > maxEncodedWriteSize {
			n = maxEncodedWriteSize
		}
		if err := connutil.WriteFull(w, p[:n]); err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}
