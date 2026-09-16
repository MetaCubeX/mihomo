//go:build windows && (amd64 || 386)

package windivert

import (
	"net"
	"runtime"

	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/log"
)

type packetBatch struct {
	tun       *Tun
	sender    int
	packets   []byte
	addresses []address
}

func newPacketBatch(t *Tun) *packetBatch {
	size := batchSize * int(t.options.MTU)
	if size < 65575 { // IPv6 header plus the largest IP payload.
		size = 65575
	}
	if size > batchBytes {
		size = batchBytes
	}
	return &packetBatch{tun: t, packets: make([]byte, 0, size), addresses: make([]address, 0, batchSize)}
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
	if _, err := b.tun.handle.sendBatch(b.packets, b.addresses, b.sender); err != nil && b.tun.ctx.Err() == nil {
		log.Warnln("[WFP] send: batch dropped: %s", err)
	}
	b.packets = b.packets[:0]
	b.addresses = b.addresses[:0]
}

type queuedPacket struct {
	data []byte
	addr address
}

type packetOutput struct {
	batches   chan *packetBatch
	datagrams chan queuedPacket
}

type packetWriter struct {
	tun     *Tun
	batches [ioParallelism]*packetBatch
}

func newPacketWriter(t *Tun) *packetWriter { return &packetWriter{tun: t} }

func packetKey(p []byte) uint32 {
	info, _ := parsePacket(p)
	return uint32(info.source.Port())<<16 | uint32(info.destination.Port())
}

func outputIndex(key uint32) int {
	// Use one sender per connection to submit its packets in order.
	key ^= key >> 16
	return int((key*0x9e3779b1)>>16) % ioParallelism
}

func (w *packetWriter) append(addr address, key uint32, parts ...[]byte) {
	sender := outputIndex(key)
	size := 0
	for _, p := range parts {
		size += len(p)
	}
	b := w.batches[sender]
	if b != nil && (len(b.addresses) == batchSize || len(b.packets)+size > cap(b.packets)) {
		w.flushOne(sender)
		b = nil
	}
	if b == nil {
		b = w.tun.batchPool.Get().(*packetBatch)
		b.sender = sender
		w.batches[sender] = b
	}
	for _, p := range parts {
		b.packets = append(b.packets, p...)
	}
	b.addresses = append(b.addresses, addr)
}

func (w *packetWriter) flushOne(sender int) {
	b := w.batches[sender]
	if b == nil {
		return
	}
	w.batches[sender] = nil
	select {
	case w.tun.output[sender].batches <- b:
	case <-w.tun.ctx.Done():
		b.packets, b.addresses = b.packets[:0], b.addresses[:0]
		w.tun.batchPool.Put(b)
	}
}

func (w *packetWriter) flush() {
	for sender := range w.batches {
		w.flushOne(sender)
	}
}

func (t *Tun) queuePacket(p []byte, addr address) error {
	if t.ctx.Err() != nil {
		_ = pool.Put(p)
		return net.ErrClosed
	}
	select {
	case t.output[outputIndex(packetKey(p))].datagrams <- queuedPacket{p, addr}:
		return nil
	case <-t.ctx.Done():
		_ = pool.Put(p)
		return net.ErrClosed
	}
}

func (t *Tun) startOutput() {
	t.batchPool.New = func() any { return newPacketBatch(t) }
	t.running.Add(ioParallelism)
	for sender := range t.output {
		output := packetOutput{batches: make(chan *packetBatch, 2), datagrams: make(chan queuedPacket, batchSize)}
		t.output[sender] = output
		go func(sender int) {
			defer t.running.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			defer func() {
				for len(output.datagrams) > 0 {
					p := <-output.datagrams
					_ = pool.Put(p.data)
				}
			}()
			for {
				select {
				case b := <-output.batches:
					for waiting := len(output.batches); waiting > 0; waiting-- {
						next := <-output.batches
						if len(b.addresses)+len(next.addresses) > batchSize || len(b.packets)+len(next.packets) > cap(b.packets) {
							b.flush()
							t.batchPool.Put(b)
							b = next
							continue
						}
						b.packets = append(b.packets, next.packets...)
						b.addresses = append(b.addresses, next.addresses...)
						next.packets, next.addresses = next.packets[:0], next.addresses[:0]
						t.batchPool.Put(next)
					}
					b.flush()
					t.batchPool.Put(b)
				case p := <-output.datagrams:
					udp := t.batchPool.Get().(*packetBatch)
					udp.sender = sender
					udp.append(p.addr, p.data)
					_ = pool.Put(p.data)
					for i := 1; i < batchSize && len(output.datagrams) > 0; i++ {
						p = <-output.datagrams
						udp.append(p.addr, p.data)
						_ = pool.Put(p.data)
					}
					udp.flush()
					t.batchPool.Put(udp)
				case <-t.ctx.Done():
					return
				}
			}
		}(sender)
	}
}
