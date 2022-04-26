package nat

import (
	"net/netip"

	"github.com/Dreamacro/clash/common/generics/list"
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
	elm := t.tuples[tuple]
	if elm == nil {
		return 0
	}

	t.available.MoveToFront(elm)

	return portBegin + elm.Value.offset
}

func (t *table) newConn(tuple tuple) uint16 {
	elm := t.available.Back()
	b := elm.Value

	delete(t.tuples, b.tuple)
	t.tuples[tuple] = elm
	b.tuple = tuple

	t.available.MoveToFront(elm)

	return portBegin + b.offset
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
