package sudoku

func (sc *Conn) decode(p, chunk []byte) (outN, consumed int, err error) {
	table, layout := sc.table, sc.table.layout
	for consumed < len(chunk) && outN < len(p) {
		i := consumed
		if sc.hintCount == 0 && i+3 < len(chunk) && layout.hintTable[chunk[i]] && layout.hintTable[chunk[i+1]] && layout.hintTable[chunk[i+2]] && layout.hintTable[chunk[i+3]] {
			val, ok := table.DecodeMap[packHintBytes(chunk[i], chunk[i+1], chunk[i+2], chunk[i+3])]
			if !ok {
				return outN, consumed, ErrInvalidSudokuMapMiss
			}
			p[outN] = val
			outN++
			consumed += 4
			continue
		}
		b := chunk[i]
		consumed++
		if !layout.hintTable[b] {
			continue
		}
		sc.hintBuf[sc.hintCount] = b
		sc.hintCount++
		if sc.hintCount != 4 {
			continue
		}
		val, ok := table.DecodeMap[packHintBytes(sc.hintBuf[0], sc.hintBuf[1], sc.hintBuf[2], sc.hintBuf[3])]
		if !ok {
			return outN, consumed, ErrInvalidSudokuMapMiss
		}
		p[outN] = val
		outN++
		sc.hintCount = 0
	}
	return outN, consumed, nil
}
