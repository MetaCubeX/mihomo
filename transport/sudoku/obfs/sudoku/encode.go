package sudoku

func encodeSudokuPayload(dst []byte, table *Table, rng randomSource, paddingThreshold uint64, p []byte) []byte {
	if len(p) == 0 {
		return dst[:0]
	}

	outCapacity := len(p)*6 + 1
	if cap(dst) < outCapacity {
		dst = make([]byte, 0, outCapacity)
	}
	out := dst[:0]
	pads := table.PaddingPool
	padLen := len(pads)

	for _, b := range p {
		if shouldPad(rng, paddingThreshold) {
			out = append(out, pads[rng.Intn(padLen)])
		}

		puzzles := table.EncodeTable[b]
		puzzle := puzzles[rng.Intn(len(puzzles))]
		perm := perm4[rng.Intn(len(perm4))]
		for _, idx := range perm {
			if shouldPad(rng, paddingThreshold) {
				out = append(out, pads[rng.Intn(padLen)])
			}
			out = append(out, puzzle[idx])
		}
	}

	if shouldPad(rng, paddingThreshold) {
		out = append(out, pads[rng.Intn(padLen)])
	}
	return out
}
