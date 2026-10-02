package nowhere

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/net/deadline"
)

type associationPacket struct {
	data []byte
	addr net.Addr
}
type associationFlow struct {
	net.PacketConn
	used atomic.Int64
}

// packetAssociation maps a mihomo PacketConn's destinations to independent
// Nowhere flows. A Nowhere wire flow itself always has exactly one target.
type packetAssociation struct {
	client        *Client
	ctx           context.Context
	cancel        context.CancelFunc
	local         net.Addr
	mu, writeMu   sync.Mutex
	flows         map[string]*associationFlow
	packets       chan associationPacket
	rd, wd        deadline.PipeDeadline
	writeDeadline time.Time
}

func (c *Client) ListenPacketAssociation(ctx context.Context, target string) (net.PacketConn, error) {
	pc, err := c.ListenPacket(ctx, target)
	if err != nil {
		return nil, err
	}
	a := &packetAssociation{client: c, local: pc.LocalAddr(), flows: make(map[string]*associationFlow), packets: make(chan associationPacket, 64), rd: deadline.MakePipeDeadline(), wd: deadline.MakePipeDeadline()}
	a.ctx, a.cancel = context.WithCancel(c.ctx)
	a.ctx = context.WithValue(a.ctx, hopsKey{}, Hops(ctx))
	f := &associationFlow{PacketConn: pc}
	f.used.Store(time.Now().UnixNano())
	a.flows[target] = f
	go a.receive(target, f)
	go a.expire()
	return a, nil
}
func (a *packetAssociation) receive(target string, f *associationFlow) {
	defer f.Close()
	defer func() {
		a.mu.Lock()
		if a.flows[target] == f {
			delete(a.flows, target)
		}
		a.mu.Unlock()
	}()
	b := make([]byte, 65535)
	for {
		n, addr, err := f.ReadFrom(b)
		if err != nil {
			return
		}
		f.used.Store(time.Now().UnixNano())
		packet := associationPacket{append([]byte{}, b[:n]...), addr}
		a.mu.Lock()
		if a.ctx.Err() != nil {
			a.mu.Unlock()
			return
		}
		select {
		case a.packets <- packet:
		default:
		}
		a.mu.Unlock()
	}
}
func (a *packetAssociation) expire() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	defer a.Close()
	for {
		select {
		case <-a.ctx.Done():
			return
		case now := <-t.C:
			var stale []*associationFlow
			a.mu.Lock()
			for target, f := range a.flows {
				if now.Sub(time.Unix(0, f.used.Load())) > 2*time.Minute {
					delete(a.flows, target)
					stale = append(stale, f)
				}
			}
			a.mu.Unlock()
			for _, f := range stale {
				f.Close()
			}
		}
	}
}
func (a *packetAssociation) Close() error {
	a.cancel()
	a.mu.Lock()
	flows := a.flows
	a.flows = make(map[string]*associationFlow)
	draining := true
	for draining {
		select {
		case <-a.packets:
		default:
			draining = false
		}
	}
	a.mu.Unlock()
	for _, f := range flows {
		f.Close()
	}
	return nil
}
func (a *packetAssociation) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case <-a.ctx.Done():
		return 0, nil, net.ErrClosed
	case <-a.rd.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	case p := <-a.packets:
		n := copy(b, p.data)
		if n < len(p.data) {
			return n, p.addr, io.ErrShortBuffer
		}
		return n, p.addr, nil
	}
}
func (a *packetAssociation) WriteTo(b []byte, addr net.Addr) (int, error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	if addr == nil {
		return 0, errors.New("nowhere: missing UDP target")
	}
	select {
	case <-a.ctx.Done():
		return 0, net.ErrClosed
	case <-a.wd.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	target := addr.String()
	a.mu.Lock()
	f := a.flows[target]
	count := len(a.flows)
	a.mu.Unlock()
	if f == nil {
		if count >= 1024 {
			return 0, SetupError(FlowLimit)
		}
		ctx, cancel := context.WithCancel(a.ctx)
		stop := make(chan struct{})
		go func() {
			select {
			case <-a.wd.Wait():
				cancel()
			case <-ctx.Done():
			case <-stop:
			}
		}()
		pc, err := a.client.ListenPacket(ctx, target)
		close(stop)
		cancel()
		if err != nil {
			return 0, err
		}
		f = &associationFlow{PacketConn: pc}
		a.mu.Lock()
		if a.ctx.Err() != nil {
			a.mu.Unlock()
			pc.Close()
			return 0, net.ErrClosed
		}
		f.used.Store(time.Now().UnixNano())
		a.flows[target] = f
		a.mu.Unlock()
		go a.receive(target, f)
	}
	a.mu.Lock()
	_ = f.SetWriteDeadline(a.writeDeadline)
	a.mu.Unlock()
	f.used.Store(time.Now().UnixNano())
	return f.WriteTo(b, addr)
}
func (a *packetAssociation) LocalAddr() net.Addr { return a.local }
func (a *packetAssociation) SetDeadline(t time.Time) error {
	a.SetReadDeadline(t)
	return a.SetWriteDeadline(t)
}
func (a *packetAssociation) SetReadDeadline(t time.Time) error { a.rd.Set(t); return nil }
func (a *packetAssociation) SetWriteDeadline(t time.Time) error {
	a.wd.Set(t)
	a.mu.Lock()
	a.writeDeadline = t
	for _, f := range a.flows {
		_ = f.SetWriteDeadline(t)
	}
	a.mu.Unlock()
	return nil
}
