package v5

import (
	"bytes"

	"github.com/metacubex/quic-go"
)

func fragWriteNative(quicConn quic.Connection, packet Packet, buf *bytes.Buffer, fragSize int) (err error) {
	fullPayload := packet.DATA
	off := 0
	fragID := uint8(0)
	fragCount := uint8((len(fullPayload) + fragSize - 1) / fragSize) // round up
	packet.FRAG_TOTAL = fragCount
	for off < len(fullPayload) {
		payloadSize := len(fullPayload) - off
		if payloadSize > fragSize {
			payloadSize = fragSize
		}
		frag := packet
		frag.FRAG_ID = fragID
		frag.SIZE = uint16(payloadSize)
		frag.DATA = fullPayload[off : off+payloadSize]
		off += payloadSize
		fragID++
		buf.Reset()
		err = frag.WriteTo(buf)
		if err != nil {
			return
		}
		data := buf.Bytes()
		err = quicConn.SendMessage(data)
		if err != nil {
			return
		}
		packet.ADDR.TYPE = AtypNone // avoid "fragment 2/2: address in non-first fragment"
	}
	return
}

type deFragger struct {
	pkgID uint16
	frags []*Packet
	count uint8
}

func (d *deFragger) Feed(m Packet) *Packet {
	if m.FRAG_TOTAL <= 1 {
		return &m
	}
	if m.FRAG_ID >= m.FRAG_TOTAL {
		// wtf is this?
		return nil
	}
	if d.count == 0 || m.PKT_ID != d.pkgID {
		// new message, clear previous state
		d.pkgID = m.PKT_ID
		d.frags = make([]*Packet, m.FRAG_TOTAL)
		d.count = 1
		d.frags[m.FRAG_ID] = &m
	} else if d.frags[m.FRAG_ID] == nil {
		d.frags[m.FRAG_ID] = &m
		d.count++
		if int(d.count) == len(d.frags) {
			// all fragments received, assemble
			var data []byte
			for _, frag := range d.frags {
				data = append(data, frag.DATA...)
			}
			p := d.frags[0] // recover from first fragment
			p.SIZE = uint16(len(data))
			p.DATA = data
			p.FRAG_ID = 0
			p.FRAG_TOTAL = 1
			d.count = 0
			return p
		}
	}
	return nil
}
