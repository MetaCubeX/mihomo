package sudoku

func encodeSudokuPayload(dst []byte, table *Table, rng *sudokuRand, paddingThreshold uint64, p []byte) []byte {
	if len(p) == 0 {
		return dst[:0]
	}
	if paddingThreshold == 0 {
		return encodeSudokuPayloadNoPadding(dst, table, rng, p)
	}

	outCapacity := len(p)*6 + 1
	if cap(dst) < outCapacity {
		dst = make([]byte, 0, outCapacity)
	}
	out := dst[:0]
	pads := table.PaddingPool
	padLen := len(pads)

	if paddingThreshold >= probOne {
		for _, b := range p {
			out = append(out, pads[rng.Intn(padLen)])

			puzzles := table.EncodeTable[b]
			puzzle := puzzles[rng.Intn(len(puzzles))]

			perm := perm4[rng.Intn(len(perm4))]
			for _, idx := range perm {
				out = append(out, pads[rng.Intn(padLen)], puzzle[idx])
			}
		}

		out = append(out, pads[rng.Intn(padLen)])
		return out
	}

	for _, b := range p {
		if uint64(rng.Uint32()) < paddingThreshold {
			out = append(out, pads[rng.Intn(padLen)])
		}

		puzzles := table.EncodeTable[b]
		puzzle := puzzles[rng.Intn(len(puzzles))]
		perm := perm4[rng.Intn(len(perm4))]
		for _, idx := range perm {
			if uint64(rng.Uint32()) < paddingThreshold {
				out = append(out, pads[rng.Intn(padLen)])
			}
			out = append(out, puzzle[idx])
		}
	}

	if uint64(rng.Uint32()) < paddingThreshold {
		out = append(out, pads[rng.Intn(padLen)])
	}
	return out
}

func appendSudokuPayload(dst []byte, table *Table, rng *sudokuRand, paddingThreshold uint64, p []byte) []byte {
	if len(p) == 0 {
		return dst
	}
	if paddingThreshold == 0 {
		return appendSudokuPayloadNoPadding(dst, table, rng, p)
	}
	pads := table.PaddingPool
	if paddingThreshold >= probOne {
		for _, b := range p {
			dst = append(dst, pads[rng.Intn(len(pads))])
			puzzle := table.EncodeTable[b][rng.Intn(len(table.EncodeTable[b]))]
			perm := perm4[rng.Intn(len(perm4))]
			for _, idx := range perm {
				dst = append(dst, pads[rng.Intn(len(pads))], puzzle[idx])
			}
		}
		return dst
	}
	for _, b := range p {
		if uint64(rng.Uint32()) < paddingThreshold {
			dst = append(dst, pads[rng.Intn(len(pads))])
		}
		puzzle := table.EncodeTable[b][rng.Intn(len(table.EncodeTable[b]))]
		perm := perm4[rng.Intn(len(perm4))]
		for _, idx := range perm {
			if uint64(rng.Uint32()) < paddingThreshold {
				dst = append(dst, pads[rng.Intn(len(pads))])
			}
			dst = append(dst, puzzle[idx])
		}
	}
	return dst
}

func appendSudokuPayloadNoPadding(dst []byte, table *Table, rng *sudokuRand, p []byte) []byte {
	for _, b := range p {
		puzzle := table.EncodeTable[b][rng.Intn(len(table.EncodeTable[b]))]
		perm := perm4[rng.Intn(len(perm4))]
		dst = append(dst, puzzle[perm[0]], puzzle[perm[1]], puzzle[perm[2]], puzzle[perm[3]])
	}
	return dst
}

func encodeSudokuPayloadNoPadding(dst []byte, table *Table, rng *sudokuRand, p []byte) []byte {
	outCapacity := len(p) * 4
	if cap(dst) < outCapacity {
		dst = make([]byte, 0, outCapacity)
	}
	out := dst[:0]

	for _, b := range p {
		puzzles := table.EncodeTable[b]
		puzzle := puzzles[rng.Intn(len(puzzles))]
		perm := perm4[rng.Intn(len(perm4))]
		out = append(out, puzzle[perm[0]], puzzle[perm[1]], puzzle[perm[2]], puzzle[perm[3]])
	}
	return out
}
