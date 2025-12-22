package sudoku

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log"
	"math/rand"
	"time"
)

var (
	ErrInvalidSudokuMapMiss = errors.New("INVALID_SUDOKU_MAP_MISS")
)

type Table struct {
	EncodeTable [256][][4]byte
	DecodeMap   map[uint32]byte
	PaddingPool []byte
	IsASCII     bool // 标记当前模式
	layout      *byteLayout
}

// NewTable initializes the obfuscation tables with built-in layouts.
// Equivalent to calling NewTableWithCustom(key, mode, "").
func NewTable(key string, mode string) *Table {
	t, err := NewTableWithCustom(key, mode, "")
	if err != nil {
		log.Panicf("failed to build table: %v", err)
	}
	return t
}

// NewTableWithCustom initializes obfuscation tables using either predefined or custom layouts.
// mode: "prefer_ascii" or "prefer_entropy". If a custom pattern is provided, ASCII mode still takes precedence.
// The customPattern must contain 8 characters with exactly 2 x, 2 p, and 4 v (case-insensitive).
func NewTableWithCustom(key string, mode string, customPattern string) (*Table, error) {
	start := time.Now()

	layout, err := resolveLayout(mode, customPattern)
	if err != nil {
		return nil, err
	}

	t := &Table{
		DecodeMap: make(map[uint32]byte),
		IsASCII:   layout.name == "ascii",
		layout:    layout,
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

	// 构建映射表
	for byteVal := 0; byteVal < 256; byteVal++ {
		targetGrid := shuffledGrids[byteVal]
		for _, positions := range combinations {
			var currentHints [4]byte

			// 1. 计算抽象提示 (Abstract Hints)
			// 我们先计算出 val 和 pos，后面再根据模式编码成 byte
			var rawParts [4]struct{ val, pos byte }

			for i, pos := range positions {
				val := targetGrid[pos] // 1..4
				rawParts[i] = struct{ val, pos byte }{val, uint8(pos)}
			}

			// 检查唯一性 (数独逻辑)
			matchCount := 0
			for _, g := range allGrids {
				match := true
				for _, p := range rawParts {
					if g[p.pos] != p.val {
						match = false
						break
					}
				}
				if match {
					matchCount++
					if matchCount > 1 {
						break
					}
				}
			}

			if matchCount == 1 {
				// 唯一确定，生成最终编码字节
				for i, p := range rawParts {
					currentHints[i] = t.layout.encodeHint(p.val-1, p.pos)
				}

				t.EncodeTable[byteVal] = append(t.EncodeTable[byteVal], currentHints)
				// 生成解码键 (需要对 Hints 进行排序以忽略传输顺序)
				key := packHintsToKey(currentHints)
				t.DecodeMap[key] = byte(byteVal)
			}
		}
	}
	log.Printf("[Init] Sudoku Tables initialized (%s) in %v", layout.name, time.Since(start))
	return t, nil
}

func packHintsToKey(hints [4]byte) uint32 {
	// Sorting network for 4 elements (Bubble sort unrolled)
	// Swap if a > b
	if hints[0] > hints[1] {
		hints[0], hints[1] = hints[1], hints[0]
	}
	if hints[2] > hints[3] {
		hints[2], hints[3] = hints[3], hints[2]
	}
	if hints[0] > hints[2] {
		hints[0], hints[2] = hints[2], hints[0]
	}
	if hints[1] > hints[3] {
		hints[1], hints[3] = hints[3], hints[1]
	}
	if hints[1] > hints[2] {
		hints[1], hints[2] = hints[2], hints[1]
	}

	return uint32(hints[0])<<24 | uint32(hints[1])<<16 | uint32(hints[2])<<8 | uint32(hints[3])
}
