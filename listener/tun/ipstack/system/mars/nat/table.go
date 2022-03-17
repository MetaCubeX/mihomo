package nat

import (
	"container/list"
	"net/netip"
)

const (
	portBegin  = 30000
	portLength = 4096
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
	tuples    map[tuple]*list.Element
	ports     [portLength]*list.Element
	available *list.List
}

func (t *table) tupleOf(port uint16) tuple {
	offset := port - portBegin
	if offset > portLength {
		return zeroTuple
	}

	elm := t.ports[offset]

	t.available.MoveToFront(elm)

	return elm.Value.(*binding).tuple
}

func (t *table) portOf(tuple tuple) uint16 {
	elm := t.tuples[tuple]
	if elm == nil {
		return 0
	}

	t.available.MoveToFront(elm)

	return portBegin + elm.Value.(*binding).offset
}

func (t *table) newConn(tuple tuple) uint16 {
	elm := t.available.Back()
	b := elm.Value.(*binding)

	delete(t.tuples, b.tuple)
	t.tuples[tuple] = elm
	b.tuple = tuple

	t.available.MoveToFront(elm)

	return portBegin + b.offset
}

func newTable() *table {
	result := &table{
		tuples:    make(map[tuple]*list.Element, portLength),
		ports:     [portLength]*list.Element{},
		available: list.New(),
	}

	for idx := range result.ports {
		result.ports[idx] = result.available.PushFront(&binding{
			tuple:  tuple{},
			offset: uint16(idx),
		})
	}

	return result
}
