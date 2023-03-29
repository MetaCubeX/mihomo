package trie

// Package succinct provides several succinct data types.
// Modify from https://github.com/openacid/succinct/sskv.go

import (
	"sort"
	"strings"

	"github.com/Dreamacro/clash/common/utils"
	"github.com/openacid/low/bitmap"
)

const (
	complexWildcardByte = byte('+')
	wildcardByte        = byte('*')
	domainStepByte      = byte('.')
)

type DomainSet struct {
	leaves, labelBitmap []uint64
	labels              []byte
	ranks, selects      []int32
}

// NewDomainSet creates a new *DomainSet struct, from a slice of sorted strings.
func NewDomainSet(keys []string) *DomainSet {
	filter := make(map[string]struct{}, len(keys))
	reserveDomains := make([]string, 0, len(keys))
	insert := func(reserveDomain string) {
		reserveDomain = utils.Reverse(reserveDomain)
		reserveDomain = strings.ToLower(reserveDomain)
		if _, ok := filter[reserveDomain]; !ok {
			filter[reserveDomain] = struct{}{}
			reserveDomains = append(reserveDomains, reserveDomain)
		}
	}
	for _, key := range keys {
		items, ok := ValidAndSplitDomain(key)
		if !ok {
			continue
		}
		if items[0] == complexWildcard {
			domain := strings.Join(items[1:], domainStep)
			insert(domain)
		}

		domain := strings.Join(items, domainStep)
		insert(domain)
	}
	sort.Slice(reserveDomains, func(i, j int) bool {
		return len(reserveDomains[i]) < len(reserveDomains[j])
	})
	keys = reserveDomains
	if len(keys) == 0 {
		return nil
	}
	ss := &DomainSet{}
	lIdx := 0

	type qElt struct{ s, e, col int }
	queue := []qElt{{0, len(keys), 0}}
	for i := 0; i < len(queue); i++ {
		elt := queue[i]
		if elt.col == len(keys[elt.s]) {
			elt.s++
			// a leaf node
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

// Has query for a key and return whether it presents in the DomainSet.
func (ss *DomainSet) Has(key string) bool {
	if ss == nil {
		return false
	}
	key = utils.Reverse(key)
	key = strings.ToLower(key)
	// no more labels in this node
	// skip character matching
	// go to next level
	nodeId, bmIdx := 0, 0

	for i := 0; i < len(key); i++ {
		c := key[i]
		for ; ; bmIdx++ {
			if getBit(ss.labelBitmap, bmIdx) != 0 {
				return false
			}
			// handle wildcard for domain
			if ss.labels[bmIdx-nodeId] == complexWildcardByte {
				return true
			} else if ss.labels[bmIdx-nodeId] == wildcardByte {
				j := i
				for ; j < len(key); j++ {
					if key[j] == domainStepByte {
						i = j
						goto END
					}
				}
				return true
			} else if ss.labels[bmIdx-nodeId] == c {
				break
			}
		}
	END:
		nodeId = countZeros(ss.labelBitmap, ss.ranks, bmIdx+1)
		bmIdx = selectIthOne(ss.labelBitmap, ss.ranks, ss.selects, nodeId-1) + 1
	}

	if getBit(ss.leaves, nodeId) != 0 {
		return true
	} else {
		return false
	}
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
func (ss *DomainSet) init() {
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
