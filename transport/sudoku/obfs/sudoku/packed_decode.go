package sudoku

func (pc *PackedConn) decode(p, chunk []byte) (outN, consumed int, err error) {
	rBuf, rBits := pc.readBitBuf, pc.readBits
	layout, padMarker := pc.table.layout, pc.padMarker
	for consumed < len(chunk) && outN < len(p) {
		i := consumed
		if rBits == 0 && outN+3 <= len(p) && i+3 < len(chunk) {
			g1, g2, g3, g4 := layout.decodeGroup[chunk[i]], layout.decodeGroup[chunk[i+1]], layout.decodeGroup[chunk[i+2]], layout.decodeGroup[chunk[i+3]]
			if (g1 | g2 | g3 | g4) < 64 {
				p[outN], p[outN+1], p[outN+2] = (g1<<2)|(g2>>4), (g2<<4)|(g3>>2), (g3<<6)|g4
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
				rBuf, rBits = 0, 0
			}
			continue
		}
		rBuf = (rBuf << 6) | uint64(group)
		rBits += 6
		if rBits >= 8 {
			rBits -= 8
			p[outN] = byte(rBuf >> rBits)
			outN++
			if rBits == 0 {
				rBuf = 0
			} else {
				rBuf &= (uint64(1) << rBits) - 1
			}
		}
	}
	pc.readBitBuf, pc.readBits = rBuf, rBits
	return outN, consumed, nil
}
