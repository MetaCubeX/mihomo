package sudoku

import "math/rand"

const probOne = uint64(1) << 32

func pickPaddingThreshold(r *rand.Rand, pMin, pMax int) uint64 {
	if r == nil {
		return 0
	}
	if pMin < 0 {
		pMin = 0
	}
	if pMax < pMin {
		pMax = pMin
	}
	if pMax > 100 {
		pMax = 100
	}
	if pMin > 100 {
		pMin = 100
	}

	min := uint64(pMin) * probOne / 100
	max := uint64(pMax) * probOne / 100
	if max <= min {
		return min
	}
	u := uint64(r.Uint32())
	return min + (u * (max - min) >> 32)
}

func shouldPad(r *rand.Rand, threshold uint64) bool {
	if threshold == 0 {
		return false
	}
	if threshold >= probOne {
		return true
	}
	if r == nil {
		return false
	}
	return uint64(r.Uint32()) < threshold
}
