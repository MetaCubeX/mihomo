//go:build windows && (amd64 || 386)

package windivert

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/pool"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
)

func TestOutputCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	device := &Tun{ctx: ctx, cancel: cancel, options: Options{MTU: 1500}}
	device.batchPool.New = func() any { return newPacketBatch(device) }
	for i := range device.output {
		device.output[i] = packetOutput{batches: make(chan *packetBatch), datagrams: make(chan queuedPacket)}
	}
	var workers sync.WaitGroup
	for i := 0; i < ioParallelism; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := device.queuePacket(pool.Get(20), address{}); err != net.ErrClosed {
				t.Errorf("queue after cancellation: %v", err)
			}
			writer := newPacketWriter(device)
			defer writer.release()
			writer.append(address{}, 0, make([]byte, 20))
			writer.flush()
		}()
	}
	cancel()
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("output producers stuck after cancellation")
	}
}

func TestStackDevicePacketOwnership(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	device := &stackDevice{tun: &Tun{ctx: ctx}, packets: make(chan []byte, 2)}
	p := []byte{1, 2, 3}
	device.deliver(p)
	p[0] = 9
	received, release, err := device.ReadPacket()
	if err != nil || received[0] != 1 {
		t.Fatalf("receive storage reused: %v %v", received, err)
	}
	release()
	device.deliver(p)
	cancel()
	_ = device.Close()
	if _, _, err := device.ReadPacket(); err != net.ErrClosed {
		t.Fatal(err)
	}
	if len(device.packets) != 0 {
		t.Fatal("queued packet retained after close")
	}
}

func TestUDPReplyValidation(t *testing.T) {
	writer := &udpWriter{destination: netip.MustParseAddrPort("192.0.2.1:1234")}
	for _, test := range []struct {
		source string
		size   int
	}{{"[2001:db8::1]:53", 1}, {"198.51.100.1:53", 65508}, {"dns.example:53", 1}} {
		if err := writer.WritePacket(buf.As(make([]byte, test.size)), M.ParseSocksaddr(test.source)); err == nil {
			t.Fatalf("invalid reply accepted: %+v", test)
		}
	}
}
