package sudoku

import (
	"fmt"
	"math/bits"
	"sort"
	"strings"
)

type byteLayout struct {
	name        string
	hintMask    byte
	hintValue   byte
	padMarker   byte
	paddingPool []byte

	hintTable   [256]bool
	encodeHint  [4][16]byte
	encodeGroup [64]byte
	decodeGroup [256]byte
	groupValid  [256]bool
}

func (l *byteLayout) isHint(b byte) bool {
	return l != nil && l.hintTable[b]
}

func (l *byteLayout) hintByte(val, pos byte) byte {
	return l.encodeHint[val&0x03][pos&0x0F]
}

func (l *byteLayout) groupByte(group byte) byte {
	return l.encodeGroup[group&0x3F]
}

func (l *byteLayout) decodePackedGroup(b byte) (byte, bool) {
	if l == nil {
		return 0, false
	}
	return l.decodeGroup[b], l.groupValid[b]
}

// resolveLayout picks the byte layout for a single traffic direction.
// ASCII always wins if requested. Custom patterns are ignored when ASCII is preferred.
func resolveLayout(mode string, customPattern string) (*byteLayout, error) {
	switch strings.ToLower(mode) {
	case "ascii", "prefer_ascii":
		return newASCIILayout(), nil
	case "entropy", "prefer_entropy", "":
		// fallback to entropy unless a custom pattern is provided
	default:
		return nil, fmt.Errorf("invalid ascii mode: %s", mode)
	}

	if strings.TrimSpace(customPattern) != "" {
		return newCustomLayout(customPattern)
	}
	return newEntropyLayout(), nil
}

func newASCIILayout() *byteLayout {
	padding := make([]byte, 0, 32)
	for i := 0; i < 32; i++ {
		padding = append(padding, byte(0x20+i))
	}

	layout := &byteLayout{
		name:        "ascii",
		hintMask:    0x40,
		hintValue:   0x40,
		padMarker:   0x3F,
		paddingPool: padding,
	}

	for val := 0; val < 4; val++ {
		for pos := 0; pos < 16; pos++ {
			b := byte(0x40 | (byte(val) << 4) | byte(pos))
			if b == 0x7F {
				b = '\n'
			}
			layout.encodeHint[val][pos] = b
		}
	}
	for group := 0; group < 64; group++ {
		b := byte(0x40 | byte(group))
		if b == 0x7F {
			b = '\n'
		}
		layout.encodeGroup[group] = b
	}
	for b := 0; b < 256; b++ {
		wire := byte(b)
		if (wire & 0x40) == 0x40 {
			layout.hintTable[wire] = true
			layout.decodeGroup[wire] = wire & 0x3F
			layout.groupValid[wire] = true
		}
	}
	layout.hintTable['\n'] = true
	layout.decodeGroup['\n'] = 0x3F
	layout.groupValid['\n'] = true

	return layout
}

func newEntropyLayout() *byteLayout {
	padding := make([]byte, 0, 16)
	for i := 0; i < 8; i++ {
		padding = append(padding, byte(0x80+i))
		padding = append(padding, byte(0x10+i))
	}

	layout := &byteLayout{
		name:        "entropy",
		hintMask:    0x90,
		hintValue:   0x00,
		padMarker:   0x80,
		paddingPool: padding,
	}

	for val := 0; val < 4; val++ {
		for pos := 0; pos < 16; pos++ {
			layout.encodeHint[val][pos] = (byte(val) << 5) | byte(pos)
		}
	}
	for group := 0; group < 64; group++ {
		v := byte(group)
		layout.encodeGroup[group] = ((v & 0x30) << 1) | (v & 0x0F)
	}
	for b := 0; b < 256; b++ {
		wire := byte(b)
		if (wire & 0x90) != 0 {
			continue
		}
		layout.hintTable[wire] = true
		layout.decodeGroup[wire] = ((wire >> 1) & 0x30) | (wire & 0x0F)
		layout.groupValid[wire] = true
	}

	return layout
}

func newCustomLayout(pattern string) (*byteLayout, error) {
	cleaned := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(pattern), " ", ""))
	if len(cleaned) != 8 {
		return nil, fmt.Errorf("custom table must have 8 symbols, got %d", len(cleaned))
	}

	var xBits, pBits, vBits []uint8
	for i, c := range cleaned {
		bit := uint8(7 - i)
		switch c {
		case 'x':
			xBits = append(xBits, bit)
		case 'p':
			pBits = append(pBits, bit)
		case 'v':
			vBits = append(vBits, bit)
		default:
			return nil, fmt.Errorf("invalid char %q in custom table", c)
		}
	}

	if len(xBits) != 2 || len(pBits) != 2 || len(vBits) != 4 {
		return nil, fmt.Errorf("custom table must contain exactly 2 x, 2 p, 4 v")
	}

	xMask := byte(0)
	for _, b := range xBits {
		xMask |= 1 << b
	}

	encodeBits := func(val, pos byte, dropX int) byte {
		var out byte
		out |= xMask
		if dropX >= 0 {
			out &^= 1 << xBits[dropX]
		}
		if (val & 0x02) != 0 {
			out |= 1 << pBits[0]
		}
		if (val & 0x01) != 0 {
			out |= 1 << pBits[1]
		}
		for i, bit := range vBits {
			if (pos>>(3-uint8(i)))&0x01 == 1 {
				out |= 1 << bit
			}
		}
		return out
	}

	paddingSet := make(map[byte]struct{})
	var padding []byte
	for drop := range xBits {
		for val := 0; val < 4; val++ {
			for pos := 0; pos < 16; pos++ {
				b := encodeBits(byte(val), byte(pos), drop)
				if bits.OnesCount8(b) >= 5 {
					if _, ok := paddingSet[b]; !ok {
						paddingSet[b] = struct{}{}
						padding = append(padding, b)
					}
				}
			}
		}
	}
	sort.Slice(padding, func(i, j int) bool { return padding[i] < padding[j] })
	if len(padding) == 0 {
		return nil, fmt.Errorf("custom table produced empty padding pool")
	}

	layout := &byteLayout{
		name:        fmt.Sprintf("custom(%s)", cleaned),
		hintMask:    xMask,
		hintValue:   xMask,
		padMarker:   padding[0],
		paddingPool: padding,
	}

	for val := 0; val < 4; val++ {
		for pos := 0; pos < 16; pos++ {
			layout.encodeHint[val][pos] = encodeBits(byte(val), byte(pos), -1)
		}
	}
	for group := 0; group < 64; group++ {
		val := byte(group>>4) & 0x03
		pos := byte(group) & 0x0F
		layout.encodeGroup[group] = encodeBits(val, pos, -1)
	}
	for b := 0; b < 256; b++ {
		wire := byte(b)
		if (wire & xMask) != xMask {
			continue
		}
		layout.hintTable[wire] = true

		var val, pos byte
		if wire&(1<<pBits[0]) != 0 {
			val |= 0x02
		}
		if wire&(1<<pBits[1]) != 0 {
			val |= 0x01
		}
		for i, bit := range vBits {
			if wire&(1<<bit) != 0 {
				pos |= 1 << (3 - uint8(i))
			}
		}
		layout.decodeGroup[wire] = (val << 4) | pos
		layout.groupValid[wire] = true
	}

	return layout, nil
}
