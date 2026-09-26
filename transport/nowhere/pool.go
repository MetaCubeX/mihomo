package nowhere

import (
	"context"
	"net"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"
)

// Initializers run outside pool locks. Waiters retain their own cancellation
// and can retry an initializer cancelled by its original caller.
func (c *Client) getQUIC(ctx context.Context) (*quicSession, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.qmu.Lock()
		if c.ctx.Err() != nil {
			c.qmu.Unlock()
			return nil, net.ErrClosed
		}
		if c.quic != nil && c.quic.conn.Context().Err() == nil {
			q := c.quic
			c.qmu.Unlock()
			return q, nil
		}
		if ready := c.quicConnecting; ready != nil {
			c.qmu.Unlock()
			select {
			case <-ready:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-c.ctx.Done():
				return nil, net.ErrClosed
			}
		}
		ready := make(chan struct{})
		c.quicConnecting = ready
		c.qmu.Unlock()
		dialCtx, cancel := context.WithCancel(ctx)
		stop := contextutils.AfterFunc(c.ctx, cancel)
		q, err := c.dialQUIC(dialCtx)
		stop()
		cancel()
		c.qmu.Lock()
		if err == nil && c.ctx.Err() != nil {
			err = net.ErrClosed
		}
		if err == nil {
			c.quic = q
		}
		c.quicConnecting = nil
		close(ready)
		c.qmu.Unlock()
		if err != nil && q != nil {
			q.Close()
			q = nil
		}
		return q, err
	}
}

func (c *Client) signalMux() {
	if c.muxChanged != nil {
		close(c.muxChanged)
	}
	c.muxChanged = make(chan struct{})
}

func (c *Client) watchMux(m *muxConn) {
	go func() {
		select {
		case <-m.done:
			c.mmu.Lock()
			c.signalMux()
			c.mmu.Unlock()
		case <-c.ctx.Done():
		}
	}()
}

// poolLoad separates application ownership from retained protocol states.
// Full carriers drain existing streams, then close to free a pool slot.
func (m *muxConn) poolLoad(id uint32) (active, pressure int, usable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.streams) >= 4096 {
		m.retiring = true
	}
	if m.retiring && m.active == 0 {
		_ = m.Close()
	}
	select {
	case <-m.done:
		return 0, 0, false
	default:
	}
	active = m.active
	for _, occupancy := range []int{
		int(int64(m.sendPeak-m.send) * 1024 / int64(m.sendPeak)),
		int(int64(connWindow-m.recv) * 1024 / connWindow),
		len(m.queue) * 1024 / cap(m.queue),
	} {
		if occupancy > pressure {
			pressure = occupancy
		}
	}
	return active, pressure, !m.retiring && m.streams[id] == nil
}

func (c *Client) dialMux(ctx context.Context) (*muxConn, error) {
	ctx, cancel := context.WithCancel(ctx)
	stopClient := contextutils.AfterFunc(c.ctx, cancel)
	defer cancel()
	defer stopClient()
	conn, err := c.dialTLS(ctx)
	if err != nil {
		return nil, err
	}
	stop := watch(ctx, conn)
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	err = writeFull(conn, []byte{255})
	stop()
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return newMux(conn, nil), nil
}

func (c *Client) acquireMux(ctx context.Context, id uint32) (*muxStream, error) {
	expand := true
	var dialErr error
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.mmu.Lock()
		if c.ctx.Err() != nil {
			c.mmu.Unlock()
			return nil, net.ErrClosed
		}
		if c.muxChanged == nil {
			c.signalMux()
		}
		var best *muxConn
		bestActive, bestPressure := 0, 0
		var draining <-chan struct{}
		live := c.mux[:0]
		for _, m := range c.mux {
			active, pressure, usable := m.poolLoad(id)
			select {
			case <-m.done:
				continue
			default:
			}
			live = append(live, m)
			if !usable {
				draining = m.done
				continue
			}
			if best == nil || active == 0 && bestActive != 0 ||
				active != 0 && bestActive != 0 && (pressure < bestPressure || pressure == bestPressure && active < bestActive) {
				best, bestActive, bestPressure = m, active, pressure
			}
		}
		c.mux = live
		capacity := len(live) + c.muxConnecting
		if best != nil && (bestActive == 0 || capacity >= 8 || !expand) {
			s, err := best.Open(id)
			c.mmu.Unlock()
			return s, err
		}
		if expand && capacity < 8 {
			c.muxConnecting++
			c.mmu.Unlock()
			m, err := c.dialMux(ctx)
			c.mmu.Lock()
			c.muxConnecting--
			if err == nil && c.ctx.Err() != nil {
				err = net.ErrClosed
			}
			if err == nil {
				c.mux = append(c.mux, m)
				c.watchMux(m)
				var s *muxStream
				s, err = m.Open(id)
				c.signalMux()
				c.mmu.Unlock()
				return s, err
			}
			c.signalMux()
			c.mmu.Unlock()
			if m != nil {
				m.Close()
			}
			expand, dialErr = false, err
			continue // A failed expansion may use an established carrier.
		}
		if dialErr != nil {
			c.mmu.Unlock()
			return nil, dialErr
		}
		changed := c.muxChanged
		wait := c.muxConnecting > 0 || draining != nil
		c.mmu.Unlock()
		if !wait {
			return nil, SetupError(FlowLimit)
		}
		select {
		case <-changed:
		case <-draining:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.ctx.Done():
			return nil, net.ErrClosed
		}
	}
}
