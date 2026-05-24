package sudoku

import (
	crypto_rand "crypto/rand"
	"encoding/binary"
	"time"
)

type sudokuRand struct {
	state      uint64
	cached     uint32
	haveCached bool
}

func newSeededRand() *sudokuRand {
	seed := time.Now().UnixNano()
	var seedBytes [8]byte
	if _, err := crypto_rand.Read(seedBytes[:]); err == nil {
		seed = int64(binary.BigEndian.Uint64(seedBytes[:]))
	}
	return newSudokuRand(seed)
}

func newSudokuRand(seed int64) *sudokuRand {
	state := uint64(seed)
	if state == 0 {
		state = 0x9e3779b97f4a7c15
	}
	return &sudokuRand{state: state}
}

func (r *sudokuRand) Uint64() uint64 {
	if r == nil {
		return 0
	}
	r.haveCached = false
	x := r.state
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	r.state = x
	return x * 0x2545f4914f6cdd1d
}

func (r *sudokuRand) Uint32() uint32 {
	if r == nil {
		return 0
	}
	if r.haveCached {
		r.haveCached = false
		return r.cached
	}
	v := r.Uint64()
	r.cached = uint32(v)
	r.haveCached = true
	return uint32(v >> 32)
}

func (r *sudokuRand) Intn(n int) int {
	if n <= 1 {
		return 0
	}
	return fastIntnFromUint32(r.Uint32(), n)
}

func fastIntnFromUint32(u uint32, n int) int {
	return int((uint64(u) * uint64(n)) >> 32)
}
