package sudoku

func appendPackedBlocks(out, p []byte, layout *byteLayout, rng *sudokuRand, threshold uint64, pads []byte) []byte {
	encode := &layout.encodeGroup
	if threshold == 0 {
		for len(p) >= 3 {
			b0, b1, b2 := p[0], p[1], p[2]
			out = append(out, encode[b0>>2], encode[(b0&3)<<4|b1>>4], encode[(b1&15)<<2|b2>>6], encode[b2&63])
			p = p[3:]
		}
		return out
	}
	for len(p) >= 3 {
		b0, b1, b2 := p[0], p[1], p[2]
		groups := [4]byte{b0 >> 2, (b0&3)<<4 | b1>>4, (b1&15)<<2 | b2>>6, b2 & 63}
		for _, group := range groups {
			if uint64(rng.Uint32()) < threshold {
				out = append(out, pads[fastIntnFromUint32(rng.Uint32(), len(pads))])
			}
			out = append(out, encode[group])
		}
		p = p[3:]
	}
	return out
}
