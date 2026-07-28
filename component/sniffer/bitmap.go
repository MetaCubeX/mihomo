package sniffer

import "math/bits"

// bitmap is a growable bitmap. Its zero value is ready for use.
type bitmap struct {
	words []uint64
}

// setRange sets every bit in the half-open interval [start, end). It panics if
// start is negative or end is less than start.
func (b *bitmap) setRange(start, end int) {
	if start < 0 || end < start {
		panic("invalid bitmap range")
	}
	if start == end {
		return
	}

	wordCount := (end-1)/64 + 1
	if wordCount > len(b.words) {
		newWordCount := uint(1) << bits.Len(uint(wordCount-1))
		if newWordCount > ^uint(0)>>1 {
			newWordCount = uint(wordCount)
		}
		words := make([]uint64, int(newWordCount))
		copy(words, b.words)
		b.words = words
	}

	firstWord := start / 64
	lastWord := (end - 1) / 64
	firstMask := ^uint64(0) << (start % 64)
	lastMask := ^uint64(0)
	if endBit := end % 64; endBit != 0 {
		lastMask = (uint64(1) << endBit) - 1
	}
	if firstWord == lastWord {
		b.words[firstWord] |= firstMask & lastMask
		return
	}

	b.words[firstWord] |= firstMask
	for i := firstWord + 1; i < lastWord; i++ {
		b.words[i] = ^uint64(0)
	}
	b.words[lastWord] |= lastMask
}

// firstUnset returns the first unset bit in [start, end), or end if all bits
// in the interval are set. It panics if start is negative or end is less than
// start.
func (b bitmap) firstUnset(start, end int) int {
	if start < 0 || end < start {
		panic("invalid bitmap range")
	}
	if start == end {
		return end
	}

	wordIndex := start / 64
	if wordIndex >= len(b.words) {
		return start
	}
	word := b.words[wordIndex] | ((uint64(1) << (start % 64)) - 1)
	for {
		if word != ^uint64(0) {
			unset := wordIndex*64 + bits.TrailingZeros64(^word)
			if unset < end {
				return unset
			}
			return end
		}

		wordIndex++
		if wordIndex*64 >= end {
			return end
		}
		if wordIndex >= len(b.words) {
			return wordIndex * 64
		}
		word = b.words[wordIndex]
	}
}
