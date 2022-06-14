package nat

import (
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

func (t *table) newConn(tuple tuple) uint16 {
	t.mux.Lock()
	elm := t.availableConn()
	b := elm.Value
	t.tuples[tuple] = elm
	b.tuple = tuple
	t.mux.Unlock()

	t.available.MoveToFront(elm)

	return portBegin + b.offset
}

func (t *table) availableConn() *list.Element[*binding] {
	elm := t.available.Back()
	offset := elm.Value.offset
	_, ok := t.tuples[t.ports[offset].Value.tuple]
	if !ok {
		if offset != 0 && offset%portLength == 0 { // resize
			tuples := make(map[tuple]*list.Element[*binding], portLength)
			maps.Copy(tuples, t.tuples)
			t.tuples = tuples
		}
		return elm
	}
	t.available.MoveToFront(elm)
	return t.availableConn()
}

func (t *table) closeConn(tuple tuple) {
	t.mux.Lock()
	delete(t.tuples, tuple)
	t.mux.Unlock()
}

func newTable() *table {
	result := &table{
		tuples:    make(map[tuple]*list.Element[*binding], portLength),
		ports:     [portLength]*list.Element[*binding]{},
		available: list.New[*binding](),
	}

	for idx := range result.ports {
		result.ports[idx] = result.available.PushFront(&binding{
			tuple:  tuple{},
			offset: uint16(idx),
		})
	}

	return result
}
