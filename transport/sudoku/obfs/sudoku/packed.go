package sudoku

import (
	"bufio"
	crypto_rand "crypto/rand"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"sync"
)

const (
	// 每次从 RNG 获取批量随机数的缓存大小，减少 RNG 函数调用开销
	RngBatchSize = 128
)

// 1. 使用 12字节->16组 的块处理优化 Write (减少循环开销)
// 2. 使用浮点随机概率判断 Padding，与纯 Sudoku 保持流量特征一致
// 3. Read 使用 copy 移动避免底层数组泄漏
type PackedConn struct {
	net.Conn
	table  *Table
	reader *bufio.Reader

	// 读缓冲
	rawBuf      []byte
	pendingData []byte // 解码后尚未被 Read 取走的字节

	// 写缓冲与状态
	writeMu  sync.Mutex
	writeBuf []byte
	bitBuf   uint64 // 暂存的位数据
	bitCount int    // 暂存的位数

	// 读状态
	readBitBuf uint64
	readBits   int

	// 随机数与填充控制 - 使用浮点随机，与 Conn 一致
	rng         *rand.Rand
	paddingRate float32 // 与 Conn 保持一致的随机概率模型
	padMarker   byte
	padPool     []byte
}

func NewPackedConn(c net.Conn, table *Table, pMin, pMax int) *PackedConn {
	var seedBytes [8]byte
	if _, err := crypto_rand.Read(seedBytes[:]); err != nil {
		binary.BigEndian.PutUint64(seedBytes[:], uint64(rand.Int63()))
	}
	seed := int64(binary.BigEndian.Uint64(seedBytes[:]))
	localRng := rand.New(rand.NewSource(seed))

	// 与 Conn 保持一致的 padding 概率计算
	min := float32(pMin) / 100.0
	rng := float32(pMax-pMin) / 100.0
	rate := min + localRng.Float32()*rng

	pc := &PackedConn{
		Conn:        c,
		table:       table,
		reader:      bufio.NewReaderSize(c, IOBufferSize),
		rawBuf:      make([]byte, IOBufferSize),
		pendingData: make([]byte, 0, 4096),
		writeBuf:    make([]byte, 0, 4096),
		rng:         localRng,
		paddingRate: rate,
	}

	pc.padMarker = table.layout.padMarker
	for _, b := range table.PaddingPool {
		if b != pc.padMarker {
			pc.padPool = append(pc.padPool, b)
		}
	}
	if len(pc.padPool) == 0 {
		pc.padPool = append(pc.padPool, pc.padMarker)
	}
	return pc
}

// maybeAddPadding 内联辅助：根据浮点概率插入 padding
func (pc *PackedConn) maybeAddPadding(out []byte) []byte {
	if pc.rng.Float32() < pc.paddingRate {
		out = append(out, pc.getPaddingByte())
	}
	return out
}

// Write 极致优化版 - 批量处理 12 字节
func (pc *PackedConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	pc.writeMu.Lock()
	defer pc.writeMu.Unlock()

	// 1. 预分配内存，避免 append 导致的多次扩容
	// 预估：原数据 * 1.5 (4/3 + padding 余量)
	needed := len(p)*3/2 + 32
	if cap(pc.writeBuf) < needed {
		pc.writeBuf = make([]byte, 0, needed)
	}
	out := pc.writeBuf[:0]

	i := 0
	n := len(p)

	// 2. 头部对齐处理 (Slow Path)
	for pc.bitCount > 0 && i < n {
		out = pc.maybeAddPadding(out)
		b := p[i]
		i++
		pc.bitBuf = (pc.bitBuf << 8) | uint64(b)
		pc.bitCount += 8
		for pc.bitCount >= 6 {
			pc.bitCount -= 6
			group := byte(pc.bitBuf >> pc.bitCount)
			if pc.bitCount == 0 {
				pc.bitBuf = 0
			} else {
				pc.bitBuf &= (1 << pc.bitCount) - 1
			}
			out = pc.maybeAddPadding(out)
			out = append(out, pc.encodeGroup(group&0x3F))
		}
	}

	// 3. 极速批量处理 (Fast Path) - 每次处理 12 字节 → 生成 16 个编码组
	for i+11 < n {
		// 处理 4 组，每组 3 字节
		for batch := 0; batch < 4; batch++ {
			b1, b2, b3 := p[i], p[i+1], p[i+2]
			i += 3

			g1 := (b1 >> 2) & 0x3F
			g2 := ((b1 & 0x03) << 4) | ((b2 >> 4) & 0x0F)
			g3 := ((b2 & 0x0F) << 2) | ((b3 >> 6) & 0x03)
			g4 := b3 & 0x3F

			// 每个组之前都有概率插入 padding
			out = pc.maybeAddPadding(out)
			out = append(out, pc.encodeGroup(g1))
			out = pc.maybeAddPadding(out)
			out = append(out, pc.encodeGroup(g2))
			out = pc.maybeAddPadding(out)
			out = append(out, pc.encodeGroup(g3))
			out = pc.maybeAddPadding(out)
			out = append(out, pc.encodeGroup(g4))
		}
	}

	// 4. 处理剩余的 3 字节块
	for i+2 < n {
		b1, b2, b3 := p[i], p[i+1], p[i+2]
		i += 3

		g1 := (b1 >> 2) & 0x3F
		g2 := ((b1 & 0x03) << 4) | ((b2 >> 4) & 0x0F)
		g3 := ((b2 & 0x0F) << 2) | ((b3 >> 6) & 0x03)
		g4 := b3 & 0x3F

		out = pc.maybeAddPadding(out)
		out = append(out, pc.encodeGroup(g1))
		out = pc.maybeAddPadding(out)
		out = append(out, pc.encodeGroup(g2))
		out = pc.maybeAddPadding(out)
		out = append(out, pc.encodeGroup(g3))
		out = pc.maybeAddPadding(out)
		out = append(out, pc.encodeGroup(g4))
	}

	// 5. 尾部处理 (Tail Path) - 处理剩余的 1 或 2 个字节
	for ; i < n; i++ {
		b := p[i]
		pc.bitBuf = (pc.bitBuf << 8) | uint64(b)
		pc.bitCount += 8
		for pc.bitCount >= 6 {
			pc.bitCount -= 6
			group := byte(pc.bitBuf >> pc.bitCount)
			if pc.bitCount == 0 {
				pc.bitBuf = 0
			} else {
				pc.bitBuf &= (1 << pc.bitCount) - 1
			}
			out = pc.maybeAddPadding(out)
			out = append(out, pc.encodeGroup(group&0x3F))
		}
	}

	// 6. 处理残留位
	if pc.bitCount > 0 {
		out = pc.maybeAddPadding(out)
		group := byte(pc.bitBuf << (6 - pc.bitCount))
		pc.bitBuf = 0
		pc.bitCount = 0
		out = append(out, pc.encodeGroup(group&0x3F))
		out = append(out, pc.padMarker)
	}

	// 尾部可能添加 padding
	out = pc.maybeAddPadding(out)

	// 发送数据
	if len(out) > 0 {
		_, err := pc.Conn.Write(out)
		pc.writeBuf = out[:0]
		return len(p), err
	}
	pc.writeBuf = out[:0]
	return len(p), nil
}

// Flush 处理最后不足 6 bit 的情况
func (pc *PackedConn) Flush() error {
	pc.writeMu.Lock()
	defer pc.writeMu.Unlock()

	out := pc.writeBuf[:0]
	if pc.bitCount > 0 {
		group := byte(pc.bitBuf << (6 - pc.bitCount))
		pc.bitBuf = 0
		pc.bitCount = 0

		out = append(out, pc.encodeGroup(group&0x3F))
		out = append(out, pc.padMarker)
	}

	// 尾部随机添加 padding
	out = pc.maybeAddPadding(out)

	if len(out) > 0 {
		_, err := pc.Conn.Write(out)
		pc.writeBuf = out[:0]
		return err
	}
	return nil
}

// Read 优化版：减少切片操作，避免内存泄漏
func (pc *PackedConn) Read(p []byte) (int, error) {
	// 1. 优先返回待处理区的数据
	if len(pc.pendingData) > 0 {
		n := copy(p, pc.pendingData)
		if n == len(pc.pendingData) {
			pc.pendingData = pc.pendingData[:0]
		} else {
			// 优化：移动剩余数据到数组头部，避免切片指向中间导致内存泄漏
			remaining := len(pc.pendingData) - n
			copy(pc.pendingData, pc.pendingData[n:])
			pc.pendingData = pc.pendingData[:remaining]
		}
		return n, nil
	}

	// 2. 循环读取直到解出数据或出错
	for {
		nr, rErr := pc.reader.Read(pc.rawBuf)
		if nr > 0 {
			// 缓存频繁访问的变量
			rBuf := pc.readBitBuf
			rBits := pc.readBits
			padMarker := pc.padMarker
			layout := pc.table.layout

			for _, b := range pc.rawBuf[:nr] {
				if !layout.isHint(b) {
					if b == padMarker {
						rBuf = 0
						rBits = 0
					}
					continue
				}

				group, ok := layout.decodeGroup(b)
				if !ok {
					return 0, ErrInvalidSudokuMapMiss
				}

				rBuf = (rBuf << 6) | uint64(group)
				rBits += 6

				if rBits >= 8 {
					rBits -= 8
					val := byte(rBuf >> rBits)
					pc.pendingData = append(pc.pendingData, val)
				}
			}

			pc.readBitBuf = rBuf
			pc.readBits = rBits
		}

		if rErr != nil {
			if rErr == io.EOF {
				pc.readBitBuf = 0
				pc.readBits = 0
			}
			if len(pc.pendingData) > 0 {
				break
			}
			return 0, rErr
		}

		if len(pc.pendingData) > 0 {
			break
		}
	}

	// 3. 返回解码后的数据 - 优化：避免底层数组泄漏
	n := copy(p, pc.pendingData)
	if n == len(pc.pendingData) {
		pc.pendingData = pc.pendingData[:0]
	} else {
		remaining := len(pc.pendingData) - n
		copy(pc.pendingData, pc.pendingData[n:])
		pc.pendingData = pc.pendingData[:remaining]
	}
	return n, nil
}

// getPaddingByte 从 Pool 中随机取 Padding 字节
func (pc *PackedConn) getPaddingByte() byte {
	return pc.padPool[pc.rng.Intn(len(pc.padPool))]
}

// encodeGroup 编码 6-bit 组
func (pc *PackedConn) encodeGroup(group byte) byte {
	return pc.table.layout.encodeGroup(group)
}
