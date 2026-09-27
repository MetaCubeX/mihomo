package sudoku

import (
	"bufio"
	"io"
	"net"
	"sync"
)

const (
	packedProtectedPrefixBytes = 14
	packedIOBufferSize         = 32 * 1024
)

// PackedConn encodes traffic with the packed Sudoku layout while preserving
// the same padding model as the regular connection.
type PackedConn struct {
	net.Conn
	table  *Table
	reader *bufio.Reader

	// Read-side buffers.

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
	if pc.bitCount == 0 && i+2 < n {
		start := i
		end := n - (n-i)%3
		out = appendPackedBlocks(out, p[start:end], layout, rng, paddingThreshold, padPool)
		i = end
	}

	for pc.bitCount > 0 && i < n {
		out = maybeAppendPackedPadding(out, rng, paddingThreshold, padPool)
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
		if _, err := pc.Conn.Write(out); err != nil {
			return len(p), err
		}
		return len(p), nil
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
		_, err := pc.Conn.Write(out)
		return err
	}
	return nil
}

func (pc *PackedConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if pc == nil || pc.Conn == nil || pc.reader == nil || pc.table == nil || pc.table.layout == nil {
		return 0, io.ErrClosedPipe
	}
	for {
		chunk, peekErr := peekBufferedChunk(pc.reader)
		if len(chunk) > 0 {
			n, consumed, decErr := pc.decode(p, chunk)
			_, _ = pc.reader.Discard(consumed)
			if decErr != nil {
				return n, decErr
			}
			if n > 0 {
				return n, nil
			}
		}
		if peekErr != nil {
			if peekErr == io.EOF {
				pc.readBitBuf, pc.readBits = 0, 0
			}
			return 0, peekErr
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
