package sudoku

import (
	"io"
	"net"
	"sync"
)

const packedProtectedPrefixBytes = 14

// PackedConn encodes traffic with the packed Sudoku layout while preserving
// the same padding model as the regular connection.
type PackedConn struct {
	net.Conn
	table  *Table
	reader *wireReader

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

// appendByte feeds one plaintext byte into the 6-bit accumulator and emits every
// group it completes.
func (pc *PackedConn) appendByte(out []byte, b byte) []byte {
	pc.bitBuf = pc.bitBuf<<8 | uint64(b)
	pc.bitCount += 8
	for pc.bitCount >= 6 {
		pc.bitCount -= 6
		group := byte(pc.bitBuf >> pc.bitCount)
		pc.bitBuf &= 1<<pc.bitCount - 1
		out = appendPackedGroup(out, pc.table.layout, pc.rng, pc.paddingThreshold, pc.padPool, group)
	}
	return out
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
		out = pc.appendByte(out, p[i])

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

// appendPackedBlocks encodes complete three-byte blocks. Keeping the no-padding
// loop separate removes the random draws and per-group append calls from it.
func appendPackedBlocks(out, p []byte, layout *byteLayout, rng *sudokuRand, threshold uint64, padPool []byte) []byte {
	encode := &layout.encodeGroup
	if threshold == 0 {
		for ; len(p) >= 3; p = p[3:] {
			b0, b1, b2 := p[0], p[1], p[2]
			out = append(out,
				encode[b0>>2],
				encode[(b0&3)<<4|b1>>4],
				encode[(b1&15)<<2|b2>>6],
				encode[b2&63])
		}
		return out
	}
	for ; len(p) >= 3; p = p[3:] {
		b0, b1, b2 := p[0], p[1], p[2]
		groups := [4]byte{b0 >> 2, (b0&3)<<4 | b1>>4, (b1&15)<<2 | b2>>6, b2 & 63}
		for _, group := range groups {
			out = maybeAppendPackedPadding(out, rng, threshold, padPool)
			out = append(out, encode[group])
		}
	}
	return out
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

	// Bound storage independently of the caller's Write size, including padding.
	out := growWriteBuf(pc.writeBuf, minInt(minInt(len(p), maxEncodedWriteSize)*3+64, maxEncodedWriteSize))
	defer func() { pc.writeBuf = releaseWriteBuf(out) }()
	layout := pc.table.layout
	rng := pc.rng
	paddingThreshold := pc.paddingThreshold
	padPool := pc.padPool

	out, i := pc.writeProtectedPrefix(out, p)
	n := len(p)

	// Align to a complete group boundary.
	for pc.bitCount > 0 && i < n {
		out = pc.appendByte(out, p[i])
		i++
	}

	end := i + (n-i)/3*3
	blockSize := 4
	if paddingThreshold != 0 {
		blockSize = 8
	}
	written := 0
	for i < end {
		// Reserve room for the final two bytes, residual marker and trailing pad.
		count := minInt((cap(out)-len(out)-8)/blockSize*3, end-i)
		if count == 0 {
			if _, err := pc.Conn.Write(out); err != nil {
				return written, err
			}
			written = i
			out = out[:0]
			continue
		}
		out = appendPackedBlocks(out, p[i:i+count], layout, rng, paddingThreshold, padPool)
		i += count
	}

	// The remaining one or two bytes stay in the accumulator.
	for ; i < n; i++ {
		out = pc.appendByte(out, p[i])
	}

	if pc.bitCount > 0 {
		group := byte(pc.bitBuf << (6 - pc.bitCount))
		pc.bitBuf = 0
		pc.bitCount = 0
		out = appendPackedGroup(out, layout, rng, paddingThreshold, padPool, group)
		out = append(out, pc.padMarker)
	}

	out = maybeAppendPackedPadding(out, rng, paddingThreshold, padPool)

	if _, err := pc.Conn.Write(out); err != nil {
		return written, err
	}
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

		out = append(out, pc.table.layout.encodeGroup[group&0x3F])
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
	if pc == nil || pc.Conn == nil || pc.table == nil || pc.table.layout == nil {
		return 0, io.ErrClosedPipe
	}
	if pc.reader == nil {
		// Write-only codecs never pay for a read buffer.
		pc.reader = &wireReader{src: pc.Conn}
	}

	outN := 0
	for {
		chunk, rErr := pc.reader.peek()
		if len(chunk) > 0 {
			var consumed int
			outN, consumed, rErr = pc.decode(p, chunk)
			pc.reader.discard(consumed)
		}

		if rErr != nil {
			if rErr == io.EOF {
				pc.readBitBuf = 0
				pc.readBits = 0
			}
			return 0, rErr
		}

		if outN > 0 {
			return outN, nil
		}
	}
}

// decode writes only as much plaintext as fits in p; the wire bytes it
// consumed can then be dropped and the rest stay in the reader.
func (pc *PackedConn) decode(p, chunk []byte) (outN, consumed int, err error) {
	rBuf := pc.readBitBuf
	rBits := pc.readBits
	padMarker := pc.padMarker
	layout := pc.table.layout

	for consumed < len(chunk) && outN < len(p) {
		i := consumed
		if rBits == 0 && outN+3 <= len(p) && i+3 < len(chunk) {
			g1 := layout.decodeGroup[chunk[i]]
			g2 := layout.decodeGroup[chunk[i+1]]
			g3 := layout.decodeGroup[chunk[i+2]]
			g4 := layout.decodeGroup[chunk[i+3]]
			// The invalid sentinel combines validation and decoding in one lookup.
			if (g1 | g2 | g3 | g4) < 64 {
				p[outN] = (g1 << 2) | (g2 >> 4)
				p[outN+1] = (g2 << 4) | (g3 >> 2)
				p[outN+2] = (g3 << 6) | g4
				outN += 3
				consumed += 4
				continue
			}
		}

		b := chunk[i]
		consumed++
		group := layout.decodeGroup[b]
		if group >= 64 {
			if b == padMarker {
				rBuf = 0
				rBits = 0
			}
			continue
		}

		rBuf = (rBuf << 6) | uint64(group)
		rBits += 6

		if rBits >= 8 {
			rBits -= 8
			p[outN] = byte(rBuf >> rBits)
			outN++
			rBuf &= (uint64(1) << rBits) - 1
		}
	}

	pc.readBitBuf = rBuf
	pc.readBits = rBits
	return outN, consumed, nil
}

func (pc *PackedConn) getPaddingByte() byte {
	return pc.padPool[pc.rng.Intn(len(pc.padPool))]
}
