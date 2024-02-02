package v5

import (
	"bytes"
	"sync"

	"github.com/metacubex/mihomo/common/lru"

	"github.com/metacubex/quic-go"
)

// MaxFragSize is a safe udp relay packet size
// because tuicv5 support udp fragment so we unneeded to do a magic modify for quic-go to increase MaxDatagramFrameSize
// it may not work fine in some platform
// "1200" from quic-go's MaxDatagramSize
// "-3" from quic-go's DatagramFrame.MaxDataLen
var MaxFragSize = 1200 - PacketOverHead - 3

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
		err = quicConn.SendDatagram(data)
		if err != nil {
			return
		}
		packet.ADDR.TYPE = AtypNone // avoid "fragment 2/2: address in non-first fragment"
	}
	return
}

type deFragger struct {
	lru  *lru.LruCache[uint16, *packetBag]
	once sync.Once
}

type packetBag struct {
	frags []*Packet
	count uint8
	mutex sync.Mutex
}

func newPacketBag() *packetBag {
	return new(packetBag)
}

func (d *deFragger) init() {
	if d.lru == nil {
		d.lru = lru.New(
			lru.WithAge[uint16, *packetBag](10),
			lru.WithUpdateAgeOnGet[uint16, *packetBag](),
		)
	}
}

func (d *deFragger) Feed(m *Packet) *Packet {
	if m.FRAG_TOTAL <= 1 {
		return m
	}
	if m.FRAG_ID >= m.FRAG_TOTAL {
		// wtf is this?
		return nil
	}
	d.once.Do(d.init) // lazy init
	bag, _ := d.lru.GetOrStore(m.PKT_ID, newPacketBag)
	bag.mutex.Lock()
	defer bag.mutex.Unlock()
	if int(m.FRAG_TOTAL) != len(bag.frags) {
		// new message, clear previous state
		bag.frags = make([]*Packet, m.FRAG_TOTAL)
		bag.count = 1
		bag.frags[m.FRAG_ID] = m
		return nil
	}
	if bag.frags[m.FRAG_ID] != nil {
		return nil
	}
	bag.frags[m.FRAG_ID] = m
	bag.count++
	if int(bag.count) != len(bag.frags) {
		return nil
	}

	// all fragments received, assemble
	var data []byte
	for _, frag := range bag.frags {
		data = append(data, frag.DATA...)
	}
	p := *bag.frags[0] // recover from first fragment
	p.SIZE = uint16(len(data))
	p.DATA = data
	p.FRAG_ID = 0
	p.FRAG_TOTAL = 1
	bag.frags = nil
	d.lru.Delete(m.PKT_ID)
	return &p
}
