package miu

import (
	"math/rand"
	"sort"
)

// Small records. Everything the lanes send outside the shaped packets — END and RESET, ServerSettings,
// the record announcing a raw segment, a short DATA — would otherwise have a length that is a fixed
// function of what it carries: END alone is always 20 bytes on the wire, a DATA holding a small inner
// record always 20 bytes longer than that record. Real HTTPS has small records too (HTTP/2 control
// frames and headers), with their own lengths. A small record is padded to a length drawn from those
// (smallUp for the client, smallDown for the server), at or above what it needs.

// recordOverhead is what TLS 1.3 adds to the plaintext of a record: the content type and the AEAD tag.
const recordOverhead = 17

// smallLimit: records that would be shorter than this (on the wire, the length field) get padded.
const smallLimit = 300

type smallLen struct{ n, count uint16 }

type lengthSampler struct {
	lens []int // ascending
	cum  []int // cum[i] = count of lens[0..i]
}

func newLengthSampler(t []smallLen) *lengthSampler {
	s := &lengthSampler{}
	total := 0
	for _, e := range t {
		total += int(e.count)
		s.lens = append(s.lens, int(e.n))
		s.cum = append(s.cum, total)
	}
	return s
}

var samplerUp, samplerDown = newLengthSampler(smallUp), newLengthSampler(smallDown)

// pick draws a length from the distribution conditioned on being at least min; 0 when none is.
func (s *lengthSampler) pick(min int) int {
	i := sort.SearchInts(s.lens, min)
	if i == len(s.lens) {
		return 0
	}
	base := 0
	if i > 0 {
		base = s.cum[i-1]
	}
	r := base + rand.Intn(s.cum[len(s.cum)-1]-base)
	return s.lens[sort.SearchInts(s.cum, r+1)]
}

var padZeros [smallLimit]byte

// padSmall returns frames preceded by a PAD frame that brings the record — the pending prefix, if any,
// and frames — to a length drawn from real small records. Records that are not small stay as they are.
// PAD goes first, after the prefix: END has to stay the last byte of its direction and RAW the last
// frame of its record. Caller holds wmu.
func (l *lane) padSmall(frames []byte) []byte {
	have := len(l.prefix) + len(frames) + recordOverhead
	if have >= smallLimit {
		return frames
	}
	s := samplerUp
	if l.server {
		s = samplerDown
	}
	want := 0
	for tries := 0; tries < 4; tries++ {
		// A PAD frame takes at least its 3-byte header: a length 1 or 2 bytes above have cannot be met.
		if w := s.pick(have); w == have || w >= have+frameHead {
			want = w
			break
		}
	}
	if want == 0 {
		want = s.pick(have + frameHead)
	}
	if want <= have {
		return frames
	}
	out := appendFrame(make([]byte, 0, want-recordOverhead-len(l.prefix)), frPad, padZeros[:want-have-frameHead])
	return append(out, frames...)
}
