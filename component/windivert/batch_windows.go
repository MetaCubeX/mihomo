//go:build windows && (amd64 || 386)

package windivert

import "github.com/metacubex/mihomo/log"

type packetBatch struct {
	tun       *Tun
	packets   []byte
	addresses []address
}

func newPacketBatch(t *Tun) *packetBatch {
	return &packetBatch{t, make([]byte, 0, batchBytes), make([]address, 0, batchSize)}
}

func (b *packetBatch) append(addr address, parts ...[]byte) {
	size := 0
	for _, p := range parts {
		size += len(p)
	}
	if len(b.addresses) == batchSize || len(b.packets)+size > cap(b.packets) {
		b.flush()
	}
	for _, p := range parts {
		b.packets = append(b.packets, p...)
	}
	b.addresses = append(b.addresses, addr)
}

func (b *packetBatch) flush() {
	if len(b.addresses) == 0 {
		return
	}
	if _, err := b.tun.handle.sendBatch(b.packets, b.addresses); err != nil && b.tun.ctx.Err() == nil {
		log.Warnln("[WFP] send: batch dropped: %s", err)
	}
	b.packets = b.packets[:0]
	b.addresses = b.addresses[:0]
}
