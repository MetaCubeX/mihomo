package nat

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/Dreamacro/clash/common/generics/list"

	"golang.org/x/exp/maps"
)

const (
	portBegin  = 30000
	portLength = 10240
)

var zeroTuple = tuple{}

type tuple struct {
	SourceAddr      netip.AddrPort
	DestinationAddr netip.AddrPort
}

type binding struct {
	tuple  tuple
	offset uint16
}

type table struct {
	tuples    map[tuple]*list.Element[*binding]
	ports     [portLength]*list.Element[*binding]
	available *list.List[*binding]
	mux       sync.Mutex
	count     uint16
}

func (t *table) tupleOf(port uint16) tuple {
	offset := port - portBegin
	if offset > portLength {
		return zeroTuple
	}

	elm := t.ports[offset]

	t.available.MoveToFront(elm)

	return elm.Value.tuple
}

func (t *table) portOf(tuple tuple) uint16 {
	t.mux.Lock()
	elm := t.tuples[tuple]
	if elm == nil {
		t.mux.Unlock()
		return 0
	}
	t.mux.Unlock()

	t.available.MoveToFront(elm)

	return portBegin + elm.Value.offset
}

func (t *table) newConn(tuple tuple) (uint16, error) {
	t.mux.Lock()
	elm, err := t.availableConn()
	if err != nil {
		t.mux.Unlock()
		return 0, err
	}

	elm.Value.tuple = tuple
	t.tuples[tuple] = elm
	t.mux.Unlock()

	return portBegin + elm.Value.offset, nil
}

func (t *table) availableConn() (*list.Element[*binding], error) {
	var elm *list.Element[*binding]

	for i := 0; i < portLength; i++ {
		elm = t.available.Back()
		t.available.MoveToFront(elm)

		offset := elm.Value.offset
		tup := t.ports[offset].Value.tuple
		if t.tuples[tup] != nil && tup.SourceAddr.IsValid() {
			continue
		}

		if t.count == portLength { // resize
			tuples := make(map[tuple]*list.Element[*binding], portLength)
			maps.Copy(tuples, t.tuples)
			t.tuples = tuples
			t.count = 1
		}
		return elm, nil
	}

	return nil, fmt.Errorf("too many open files, limits [%d, %d]", portLength, len(t.tuples))
}

func (t *table) closeConn(tuple tuple) {
	t.mux.Lock()
	delete(t.tuples, tuple)
	t.count++
	t.mux.Unlock()
}

func newTable() *table {
	result := &table{
		tuples:    make(map[tuple]*list.Element[*binding], portLength),
		ports:     [portLength]*list.Element[*binding]{},
		available: list.New[*binding](),
		count:     1,
	}

	for idx := range result.ports {
		result.ports[idx] = result.available.PushFront(&binding{
			tuple:  tuple{},
			offset: uint16(idx),
		})
	}

	return result
}
