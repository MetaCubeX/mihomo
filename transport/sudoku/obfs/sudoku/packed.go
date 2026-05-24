package sudoku

import (
	"bufio"
	"io"
	"net"
	"sync"
)

const (
	packedProtectedPrefixBytes = 14
	packedIOBufferSize         = 64 * 1024
	packedDecodeBufferSize     = 96 * 1024
)

// PackedConn encodes traffic with the packed Sudoku layout while preserving
// the same padding model as the regular connection.
type PackedConn struct {
	net.Conn
	table  *Table
	reader *bufio.Reader

	// Read-side buffers.
	rawBuf      []byte
	pendingData pendingBuffer

	// Write-side state.
	writeMu  sync.Mutex
	writeBuf []byte
	bitBuf   uint64
	bitCount int

	// Read-side bit accumulator.
	readBitBuf uint64
	readBits   int

	// Padding selection matches Conn's threshold-based model.
	rng              *sudokuRand
	paddingThreshold uint64
	padMarker        byte
	padPool          []byte
}

func (pc *PackedConn) CloseWrite() error {
	if pc == nil || pc.Conn == nil {
		return nil
	}
	if cw, ok := pc.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (pc *PackedConn) CloseRead() error {
	if pc == nil || pc.Conn == nil {
		return nil
	}
	if cr, ok := pc.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

func NewPackedConn(c net.Conn, table *Table, pMin, pMax int) *PackedConn {
	localRng := newSeededRand()

	pc := &PackedConn{
		Conn:             c,
		table:            table,
		reader:           bufio.NewReaderSize(c, packedIOBufferSize),
		rawBuf:           make([]byte, packedDecodeBufferSize),
		pendingData:      newPendingBuffer(4096),
		writeBuf:         make([]byte, 0, 4096),
		rng:              localRng,
		paddingThreshold: pickPaddingThreshold(localRng, pMin, pMax),
	}

	if table != nil && table.layout != nil {
		pc.padMarker = table.layout.padMarker
		for _, b := range table.PaddingPool {
			if b != pc.padMarker {
				pc.padPool = append(pc.padPool, b)
			}
		}
	}
	if len(pc.padPool) == 0 {
		pc.padPool = append(pc.padPool, pc.padMarker)
	}
	return pc
}

func (pc *PackedConn) appendForcedPadding(out []byte) []byte {
	return append(out, pc.getPaddingByte())
}

func (pc *PackedConn) nextProtectedPrefixGap() int {
	return 1 + pc.rng.Intn(2)
}

func (pc *PackedConn) writeProtectedPrefix(out []byte, p []byte) ([]byte, int) {
	if len(p) == 0 {
		return out, 0
	}

	limit := len(p)
	if limit > packedProtectedPrefixBytes {
		limit = packedProtectedPrefixBytes
	}

	for padCount := 0; padCount < 1+pc.rng.Intn(2); padCount++ {
		out = pc.appendForcedPadding(out)
	}

	gap := pc.nextProtectedPrefixGap()
	effective := 0
	for i := 0; i < limit; i++ {
		pc.bitBuf = (pc.bitBuf << 8) | uint64(p[i])
		pc.bitCount += 8
		for pc.bitCount >= 6 {
			pc.bitCount -= 6
			group := byte(pc.bitBuf >> pc.bitCount)
			if pc.bitCount == 0 {
				pc.bitBuf = 0
			} else {
				pc.bitBuf &= (1 << pc.bitCount) - 1
			}
			out = appendPackedGroup(out, pc.table.layout, pc.rng, pc.paddingThreshold, pc.padPool, group)
		}

		effective++
		if effective >= gap {
			out = pc.appendForcedPadding(out)
			effective = 0
			gap = pc.nextProtectedPrefixGap()
		}
	}

	return out, limit
}

func appendPackedGroup(out []byte, layout *byteLayout, rng *sudokuRand, paddingThreshold uint64, padPool []byte, group byte) []byte {
	if paddingThreshold != 0 {
		u := rng.Uint32()
		if uint64(u) < paddingThreshold {
			out = append(out, padPool[fastIntnFromUint32(rng.Uint32(), len(padPool))])
		}
	}
	return append(out, layout.encodeGroup[group&0x3F])
}

func maybeAppendPackedPadding(out []byte, rng *sudokuRand, paddingThreshold uint64, padPool []byte) []byte {
	if paddingThreshold != 0 {
		u := rng.Uint32()
		if uint64(u) < paddingThreshold {
			out = append(out, padPool[fastIntnFromUint32(rng.Uint32(), len(padPool))])
		}
	}
	return out
}

func (pc *PackedConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if pc == nil || pc.Conn == nil || pc.table == nil || pc.table.layout == nil || pc.rng == nil || len(pc.padPool) == 0 {
		return 0, io.ErrClosedPipe
	}

	pc.writeMu.Lock()
	defer pc.writeMu.Unlock()

	needed := len(p)*3/2 + 32
	if pc.paddingThreshold == 0 {
		needed = ((len(p)+2)/3)*4 + 32
	}
	if cap(pc.writeBuf) < needed {
		pc.writeBuf = make([]byte, 0, needed)
	}
	out := pc.writeBuf[:0]
	layout := pc.table.layout
	rng := pc.rng
	paddingThreshold := pc.paddingThreshold
	padPool := pc.padPool

	var prefixN int
	out, prefixN = pc.writeProtectedPrefix(out, p)

	i := prefixN
	n := len(p)

	for pc.bitCount > 0 && i < n {
		b := p[i]
		i++
		pc.bitBuf = (pc.bitBuf << 8) | uint64(b)
		pc.bitCount += 8
		for pc.bitCount >= 6 {
			pc.bitCount -= 6
			group := byte(pc.bitBuf >> pc.bitCount)
			if pc.bitCount == 0 {
				pc.bitBuf = 0
			} else {
				pc.bitBuf &= (1 << pc.bitCount) - 1
			}
			out = appendPackedGroup(out, layout, rng, paddingThreshold, padPool, group)
		}
	}

	for i+11 < n {
		for batch := 0; batch < 4; batch++ {
			b1, b2, b3 := p[i], p[i+1], p[i+2]
			i += 3

			g1 := (b1 >> 2) & 0x3F
			g2 := ((b1 & 0x03) << 4) | ((b2 >> 4) & 0x0F)
			g3 := ((b2 & 0x0F) << 2) | ((b3 >> 6) & 0x03)
			g4 := b3 & 0x3F

			out = appendPackedGroup(out, layout, rng, paddingThreshold, padPool, g1)
			out = appendPackedGroup(out, layout, rng, paddingThreshold, padPool, g2)
			out = appendPackedGroup(out, layout, rng, paddingThreshold, padPool, g3)
			out = appendPackedGroup(out, layout, rng, paddingThreshold, padPool, g4)
		}
	}

	for i+2 < n {
		b1, b2, b3 := p[i], p[i+1], p[i+2]
		i += 3

		g1 := (b1 >> 2) & 0x3F
		g2 := ((b1 & 0x03) << 4) | ((b2 >> 4) & 0x0F)
		g3 := ((b2 & 0x0F) << 2) | ((b3 >> 6) & 0x03)
		g4 := b3 & 0x3F

		out = appendPackedGroup(out, layout, rng, paddingThreshold, padPool, g1)
		out = appendPackedGroup(out, layout, rng, paddingThreshold, padPool, g2)
		out = appendPackedGroup(out, layout, rng, paddingThreshold, padPool, g3)
		out = appendPackedGroup(out, layout, rng, paddingThreshold, padPool, g4)
	}

	for ; i < n; i++ {
		b := p[i]
		pc.bitBuf = (pc.bitBuf << 8) | uint64(b)
		pc.bitCount += 8
		for pc.bitCount >= 6 {
			pc.bitCount -= 6
			group := byte(pc.bitBuf >> pc.bitCount)
			if pc.bitCount == 0 {
				pc.bitBuf = 0
			} else {
				pc.bitBuf &= (1 << pc.bitCount) - 1
			}
			out = appendPackedGroup(out, layout, rng, paddingThreshold, padPool, group)
		}
	}

	if pc.bitCount > 0 {
		group := byte(pc.bitBuf << (6 - pc.bitCount))
		pc.bitBuf = 0
		pc.bitCount = 0
		out = appendPackedGroup(out, layout, rng, paddingThreshold, padPool, group)
		out = append(out, pc.padMarker)
	}

	out = maybeAppendPackedPadding(out, rng, paddingThreshold, padPool)

	if len(out) > 0 {
		pc.writeBuf = out[:0]
		return len(p), writeFull(pc.Conn, out)
	}
	pc.writeBuf = out[:0]
	return len(p), nil
}

func (pc *PackedConn) Flush() error {
	if pc == nil || pc.Conn == nil || pc.table == nil || pc.table.layout == nil || pc.rng == nil || len(pc.padPool) == 0 {
		return io.ErrClosedPipe
	}

	pc.writeMu.Lock()
	defer pc.writeMu.Unlock()

	out := pc.writeBuf[:0]
	if pc.bitCount > 0 {
		group := byte(pc.bitBuf << (6 - pc.bitCount))
		pc.bitBuf = 0
		pc.bitCount = 0

		out = append(out, pc.table.layout.groupByte(group&0x3F))
		out = append(out, pc.padMarker)
	}

	out = maybeAppendPackedPadding(out, pc.rng, pc.paddingThreshold, pc.padPool)

	if len(out) > 0 {
		pc.writeBuf = out[:0]
		return writeFull(pc.Conn, out)
	}
	return nil
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func (pc *PackedConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if pc == nil || pc.Conn == nil || pc.reader == nil || len(pc.rawBuf) == 0 || pc.table == nil || pc.table.layout == nil {
		return 0, io.ErrClosedPipe
	}
	if n, ok := drainPending(p, &pc.pendingData); ok {
		return n, nil
	}

	outN := 0
	for {
		nr, rErr := readRawLimited(pc.Conn, pc.reader, pc.rawBuf[:packedReadSize(len(p)-outN, len(pc.rawBuf))])
		if nr > 0 {
			rBuf := pc.readBitBuf
			rBits := pc.readBits
			padMarker := pc.padMarker
			layout := pc.table.layout

			chunk := pc.rawBuf[:nr]
			for i := 0; i < len(chunk); {
				if rBits == 0 && outN+3 <= len(p) && i+3 < len(chunk) &&
					layout.hintTable[chunk[i]] && layout.hintTable[chunk[i+1]] &&
					layout.hintTable[chunk[i+2]] && layout.hintTable[chunk[i+3]] {
					g1 := layout.decodeGroup[chunk[i]]
					g2 := layout.decodeGroup[chunk[i+1]]
					g3 := layout.decodeGroup[chunk[i+2]]
					g4 := layout.decodeGroup[chunk[i+3]]
					p[outN] = (g1 << 2) | (g2 >> 4)
					p[outN+1] = (g2 << 4) | (g3 >> 2)
					p[outN+2] = (g3 << 6) | g4
					outN += 3
					i += 4
					continue
				}

				b := chunk[i]
				i++
				if !layout.hintTable[b] {
					if b == padMarker {
						rBuf = 0
						rBits = 0
					}
					continue
				}

				group, ok := layout.decodePackedGroup(b)
				if !ok {
					return 0, ErrInvalidSudokuMapMiss
				}

				rBuf = (rBuf << 6) | uint64(group)
				rBits += 6

				if rBits >= 8 {
					rBits -= 8
					val := byte(rBuf >> rBits)
					outN = appendDecodedByte(p, outN, &pc.pendingData, val)
					if rBits == 0 {
						rBuf = 0
					} else {
						rBuf &= (uint64(1) << rBits) - 1
					}
				}
			}

			pc.readBitBuf = rBuf
			pc.readBits = rBits
		}

		if rErr != nil {
			if rErr == io.EOF {
				pc.readBitBuf = 0
				pc.readBits = 0
			}
			if outN > 0 {
				return outN, nil
			}
			if n, ok := drainPending(p, &pc.pendingData); ok {
				return n, nil
			}
			return 0, rErr
		}

		if outN > 0 {
			return outN, nil
		}
	}
}

func (pc *PackedConn) getPaddingByte() byte {
	return pc.padPool[pc.rng.Intn(len(pc.padPool))]
}

func packedReadSize(decodedRemaining, maxRaw int) int {
	if maxRaw <= minDecodeReadSize || decodedRemaining <= 0 {
		return maxRaw
	}
	if decodedRemaining > (maxRaw-minDecodeReadSize)/2 {
		return maxRaw
	}

	return decodedRemaining*2 + minDecodeReadSize
}
