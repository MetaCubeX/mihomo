package sudoku

import (
	"encoding/binary"
	"math"
)

const (
	// maxPaddedExpansion is the worst case per plaintext byte: five padding
	// slots and four hints.
	maxPaddedExpansion = 9
	// encodeSlack is the headroom the encoder needs past the last byte it keeps,
	// so each plaintext byte can be stored as one fixed-size array write.
	encodeSlack = 16
)

// permShifts[i][j] is the bit offset, inside a packed puzzle, of the hint that
// the i-th hint order places in slot j. The orders are the 24 permutations of
// 0..3 in lexicographic order.
var permShifts = buildPermShifts()

func buildPermShifts() (shifts [24][4]uint8) {
	n := 0
	for a := uint8(0); a < 4; a++ {
		for b := uint8(0); b < 4; b++ {
			for c := uint8(0); c < 4; c++ {
				for d := uint8(0); d < 4; d++ {
					if a == b || a == c || a == d || b == c || b == d || c == d {
						continue
					}
					shifts[n] = [4]uint8{8 * a, 8 * b, 8 * c, 8 * d}
					n++
				}
			}
		}
	}
	return shifts
}

// permute reorders the four hint bytes of a packed puzzle.
func permute(puzzle uint32, s *[4]uint8) uint32 {
	return puzzle>>(s[0]&31)&0xff |
		puzzle>>(s[1]&31)&0xff<<8 |
		puzzle>>(s[2]&31)&0xff<<16 |
		puzzle>>(s[3]&31)<<24
}

// pickPuzzle draws one puzzle of plaintext byte b and one hint order from a
// single 64-bit random value.
func (t *Table) pickPuzzle(b byte, draw uint64) uint32 {
	puzzles := t.EncodeTable[b]
	puzzle := puzzles[(draw>>32)*uint64(len(puzzles))>>32]
	return permute(binary.LittleEndian.Uint32(puzzle[:]), &permShifts[(draw&math.MaxUint32)*uint64(len(permShifts))>>32])
}

// padSlot writes a candidate padding byte at w[k] and keeps it only when the
// slot's draw falls under threshold. A slot that draws no padding leaves k
// alone, so the next write overwrites the candidate.
func padSlot(state, threshold uint64, pool []byte, w *[16]byte, k int) (uint64, int) {
	state, draw := wyNext(state)
	w[k&15] = pool[(draw>>32)*uint64(len(pool))>>32]
	return state, k + int((draw&math.MaxUint32-threshold)>>63)
}

// appendSudokuPayload encodes p after dst. Each plaintext byte becomes one
// puzzle's four hints in a random order, with a padding byte possible before
// each hint and one more before the group. threshold is the per-slot padding
// probability scaled to 1<<32, so a value of 1<<32 pads every slot.
func appendSudokuPayload(dst []byte, table *Table, rng *sudokuRand, threshold uint64, p []byte) []byte {
	if len(p) == 0 {
		return dst
	}
	n := len(dst)
	expansion := maxPaddedExpansion
	if threshold == 0 {
		expansion = 4
	}
	out := dst
	if need := n + len(p)*expansion + encodeSlack; cap(out) < need {
		out = make([]byte, n, need)
		copy(out, dst)
	}
	out = out[:cap(out)]
	state := rng.state

	if threshold == 0 {
		for _, b := range p {
			var draw uint64
			state, draw = wyNext(state)
			binary.LittleEndian.PutUint32(out[n:], table.pickPuzzle(b, draw))
			n += 4
		}
		rng.state = state
		return out[:n]
	}

	pool := table.PaddingPool
	for _, b := range p {
		var draw uint64
		state, draw = wyNext(state)
		hints := table.pickPuzzle(b, draw)

		w := (*[16]byte)(out[n:])
		var k int
		state, k = padSlot(state, threshold, pool, w, 0)
		state, k = padSlot(state, threshold, pool, w, k)
		w[k&15] = byte(hints)
		state, k = padSlot(state, threshold, pool, w, k+1)
		w[k&15] = byte(hints >> 8)
		state, k = padSlot(state, threshold, pool, w, k+1)
		w[k&15] = byte(hints >> 16)
		state, k = padSlot(state, threshold, pool, w, k+1)
		w[k&15] = byte(hints >> 24)
		n += k + 1
	}
	rng.state = state
	return out[:n]
}
