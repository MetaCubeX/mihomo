package sudoku

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"
	"math/rand"
	"strings"
)

var (
	ErrInvalidSudokuMapMiss = errors.New("INVALID_SUDOKU_MAP_MISS")
)

type Table struct {
	EncodeTable [256][][4]byte
	PaddingPool []byte
	IsASCII     bool // 标记当前模式
	layout      *byteLayout
	opposite    *Table
	hint        uint32

	// hintSets[pos<<2|val] holds bit k when the k-th shuffled grid has val at
	// pos. Four hints identify a plaintext byte exactly when their sets share a
	// single grid, and that grid's rank is the byte.
	hintSets [128][5]uint64
}

// NewTable initializes the obfuscation tables with built-in layouts.
// Equivalent to calling NewTableWithCustom(key, mode, "").
func NewTable(key string, mode string) *Table {
	t, err := NewTableWithCustom(key, mode, "")
	if err != nil {
		panic(err)
	}
	return t
}

// NewTableWithCustom initializes the uplink/probe Sudoku table using either predefined
// or directional layouts. Directional modes such as "up_ascii_down_entropy" return the
// client->server table and internally attach the opposite direction table for runtime use.
// The customPattern must contain 8 characters with exactly 2 x, 2 p, and 4 v (case-insensitive).
func NewTableWithCustom(key string, mode string, customPattern string) (*Table, error) {
	asciiMode, err := ParseASCIIMode(mode)
	if err != nil {
		return nil, err
	}

	uplinkPattern := customPatternForToken(asciiMode.Uplink, customPattern)
	downlinkPattern := customPatternForToken(asciiMode.Downlink, customPattern)
	hint := tableHintFingerprint(key, asciiMode.Canonical(), uplinkPattern, downlinkPattern)

	uplink, err := newSingleDirectionTable(key, asciiMode.uplinkPreference(), uplinkPattern)
	if err != nil {
		return nil, err
	}
	uplink.hint = hint
	if asciiMode.Uplink == asciiMode.Downlink {
		uplink.opposite = uplink
		return uplink, nil
	}

	downlink, err := newSingleDirectionTable(key, asciiMode.downlinkPreference(), downlinkPattern)
	if err != nil {
		return nil, err
	}
	downlink.hint = hint
	uplink.opposite = downlink
	downlink.opposite = uplink
	return uplink, nil
}

func newSingleDirectionTable(key string, mode string, customPattern string) (*Table, error) {
	layout, err := resolveLayout(mode, customPattern)
	if err != nil {
		return nil, err
	}

	t := &Table{
		IsASCII: layout.name == "ascii",
		layout:  layout,
	}
	t.PaddingPool = append(t.PaddingPool, layout.paddingPool...)

	// 生成数独网格 (逻辑不变)
	allGrids := GenerateAllGrids()
	h := sha256.New()
	h.Write([]byte(key))
	seed := int64(binary.BigEndian.Uint64(h.Sum(nil)[:8]))
	rng := rand.New(rand.NewSource(seed))

	shuffledGrids := make([]Grid, 288)
	copy(shuffledGrids, allGrids)
	rng.Shuffle(len(shuffledGrids), func(i, j int) {
		shuffledGrids[i], shuffledGrids[j] = shuffledGrids[j], shuffledGrids[i]
	})

	// 预计算组合
	var combinations [][]int
	var combine func(int, int, []int)
	combine = func(s, k int, c []int) {
		if k == 0 {
			tmp := make([]int, len(c))
			copy(tmp, c)
			combinations = append(combinations, tmp)
			return
		}
		for i := s; i <= 16-k; i++ {
			c = append(c, i)
			combine(i+1, k-1, c)
			c = c[:len(c)-1]
		}
	}
	combine(0, 4, []int{})

	for k, g := range shuffledGrids {
		for pos, val := range g {
			t.hintSets[pos<<2|int(val-1)][k>>6] |= 1 << (k & 63)
		}
	}

	// 构建映射表
	for byteVal := 0; byteVal < 256; byteVal++ {
		targetGrid := shuffledGrids[byteVal]
		for _, positions := range combinations {
			var hints [4]uint8
			for i, pos := range positions {
				hints[i] = uint8(pos)<<2 | (targetGrid[pos] - 1)
			}

			// 唯一确定才可作为 puzzle
			if _, ok := t.decodeHints(hints[0], hints[1], hints[2], hints[3]); !ok {
				continue
			}

			var currentHints [4]byte
			for i, pos := range positions {
				currentHints[i] = t.layout.hintByte(targetGrid[pos]-1, uint8(pos))
			}
			t.EncodeTable[byteVal] = append(t.EncodeTable[byteVal], currentHints)
		}
	}
	return t, nil
}

func customPatternForToken(token string, customPattern string) string {
	if token == asciiModeTokenEntropy {
		return customPattern
	}
	return ""
}

func (t *Table) OppositeDirection() *Table {
	if t == nil || t.opposite == nil {
		return t
	}
	return t.opposite
}

func (t *Table) Hint() uint32 {
	if t == nil {
		return 0
	}
	return t.hint
}

func tableHintFingerprint(key string, mode string, uplinkPattern string, downlinkPattern string) uint32 {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"sudoku-table-hint",
		key,
		mode,
		strings.ToLower(strings.TrimSpace(uplinkPattern)),
		strings.ToLower(strings.TrimSpace(downlinkPattern)),
	}, "\x00")))
	return binary.BigEndian.Uint32(sum[:4])
}

// decodeHints returns the plaintext byte whose puzzle is exactly these four
// hint indexes (pos<<2|val, or poisonHint).
func (t *Table) decodeHints(a, b, c, d uint8) (byte, bool) {
	sa, sb, sc, sd := &t.hintSets[a&127], &t.hintSets[b&127], &t.hintSets[c&127], &t.hintSets[d&127]
	r0 := sa[0] & sb[0] & sc[0] & sd[0]
	r1 := sa[1] & sb[1] & sc[1] & sd[1]
	r2 := sa[2] & sb[2] & sc[2] & sd[2]
	r3 := sa[3] & sb[3] & sc[3] & sd[3]
	r4 := sa[4] & sb[4] & sc[4] & sd[4]

	// Exactly one shared grid, and it must be one of the 256 that carry a byte.
	multi := r0&(r0-1) | r1&(r1-1) | r2&(r2-1) | r3&(r3-1) | r4
	var nonEmpty uint64
	word := 0
	if r1 != 0 {
		nonEmpty++
		word = 64
	}
	if r2 != 0 {
		nonEmpty++
		word = 128
	}
	if r3 != 0 {
		nonEmpty++
		word = 192
	}
	if r0 != 0 {
		nonEmpty++
	}
	rank := word + bits.TrailingZeros64(r0|r1|r2|r3)
	return byte(rank), multi|(nonEmpty^1) == 0
}
