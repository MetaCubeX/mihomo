package domain

import (
	"reflect"
	"slices"
	"unsafe"

	"github.com/openacid/low/bitmap"
)

// mod from https://github.com/openacid/succinct

const prefixLabel = '\r'

type Set struct {
	leaves, labelBitmap []uint64
	labels              []byte
	ranks, selects      []int32
}

// NewSet creates a new *Set struct, from a slice of sorted strings.
func NewSet(strs []string) *Set {

	keys := make([]string, 0, len(strs))
	seen := make(map[string]bool, len(strs))
	for _, v := range strs {
		if seen[v] {
			continue
		}
		seen[v] = true
		keys = append(keys, reverseDomainSuffix(v))
	}

	slices.Sort(keys)
	ss := &Set{}
	lIdx := 0

	type qElt struct{ s, e, col int }

	queue := []qElt{{0, len(keys), 0}}

	for i := 0; i < len(queue); i++ {
		elt := queue[i]

		if elt.col == len(keys[elt.s]) {
			// a leaf node
			elt.s++
			setBit(&ss.leaves, i, 1)
		}

		for j := elt.s; j < elt.e; {

			frm := j

			for ; j < elt.e && keys[j][elt.col] == keys[frm][elt.col]; j++ {
			}

			queue = append(queue, qElt{frm, j, elt.col + 1})
			ss.labels = append(ss.labels, keys[frm][elt.col])
			setBit(&ss.labelBitmap, lIdx, 0)
			lIdx++
		}

		setBit(&ss.labelBitmap, lIdx, 1)
		lIdx++
	}

	ss.init()
	return ss
}

// Has query for a key and return whether it presents in the Set.
func (ss *Set) Has(key string) bool {
	kbs := s2b(key)
	klen := len(kbs)
	nodeId, bmIdx := 0, 0

	for i := klen - 1; i >= 0; i-- {
		c := kbs[i]
		for ; ; bmIdx++ {
			//log.Printf("%c", c)
			if getBit(ss.labelBitmap, bmIdx) != 0 {
				// no more labels in this node
				//if c == '.' {
				//	return true
				//} else {
				//	return false
				//}
				return false
			}

			la := ss.labels[bmIdx-nodeId]
			// isPrefix := la == '\r'
			// if isPrefix {
			// 	log.Printf("%c '/r' \n", c)
			// } else {
			// 	log.Printf("%c '%c'\n", c, la)
			// }

			if c == '.' && la == prefixLabel {
				return true
			}
			if la == c {
				break
			}
		}
		// log.Printf("%c\n", c)
		// go to next level

		nodeId = countZeros(ss.labelBitmap, ss.ranks, bmIdx+1)
		bmIdx = selectIthOne(ss.labelBitmap, ss.ranks, ss.selects, nodeId-1) + 1
	}

	return ss.labels[bmIdx-nodeId] == prefixLabel
}

func setBit(bm *[]uint64, i int, v int) {
	for i>>6 >= len(*bm) {
		*bm = append(*bm, 0)
	}
	(*bm)[i>>6] |= uint64(v) << uint(i&63)
}

func getBit(bm []uint64, i int) uint64 {
	return bm[i>>6] & (1 << uint(i&63))
}

// init builds pre-calculated cache to speed up rank() and select()
func (ss *Set) init() {
	ss.selects, ss.ranks = bitmap.IndexSelect32R64(ss.labelBitmap)
}

// countZeros counts the number of "0" in a bitmap before the i-th bit(excluding
// the i-th bit) on behalf of rank index.
// E.g.:
//
//	countZeros("010010", 4) == 3
//	//          012345
func countZeros(bm []uint64, ranks []int32, i int) int {
	a, _ := bitmap.Rank64(bm, ranks, int32(i))
	return i - int(a)
}

// selectIthOne returns the index of the i-th "1" in a bitmap, on behalf of rank
// and select indexes.
// E.g.:
//
//	selectIthOne("010010", 1) == 4
//	//            012345
func selectIthOne(bm []uint64, ranks, selects []int32, i int) int {
	a, _ := bitmap.Select32R64(bm, selects, ranks, int32(i))
	return int(a)
}

func reverseDomainSuffix(domain string) string {
	l := len(domain)
	b := []byte(domain)
	for i := 0; i < l/2; i++ {
		b[i] = domain[l-i-1]
		b[l-i-1] = domain[i]
	}
	b = append(b, prefixLabel)
	return string(b)
}

func s2b(s string) (b []byte) {
	bh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	bh.Data = sh.Data
	bh.Cap = sh.Len
	bh.Len = sh.Len
	return b
}

func (ss *Set) Size() int {
	// leaves, labelBitmap []uint64
	// labels              []byte
	// ranks, selects      []int32
	leavesSize := cap(ss.leaves) * 8
	labelBitmapSize := cap(ss.labelBitmap) * 8
	labelsSize := cap(ss.labels)
	ranksSize := cap(ss.ranks) * 4
	selectsSize := cap(ss.selects) * 4

	return leavesSize + labelBitmapSize + labelsSize + ranksSize + selectsSize
}
