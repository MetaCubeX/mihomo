package httpmask

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/metacubex/tls"
)

const (
	preconnectedConnTTL      = 4 * time.Second
	tunnelPreconnectCount    = 3
	tunnelMuxPreconnectCount = tunnelPreconnectCount + 1
	maxPreconnectedConns     = 64
	tunnelTLSHandshakeLimit  = 10 * time.Second
)

type preparedConn struct {
	conn      net.Conn
	expiresAt time.Time
	release   func()
}

func (c *preparedConn) releaseSlot() {
	if c != nil && c.release != nil {
		c.release()
		c.release = nil
	}
}

type preconnectLimiter struct {
	slots chan struct{}
}

func newPreconnectLimiter(limit int) *preconnectLimiter {
	if limit <= 0 {
		return nil
	}
	return &preconnectLimiter{slots: make(chan struct{}, limit)}
}

func (l *preconnectLimiter) acquire() (func(), bool) {
	if l == nil {
		return func() {}, true
	}
	select {
	case l.slots <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() { <-l.slots })
		}, true
	default:
		return nil, false
	}
}

type preparedConnPool struct {
	mu      sync.Mutex
	ready   []*preparedConn
	pending int
	changed chan struct{}
	refill  chan struct{}
	closed  bool
	limiter *preconnectLimiter
}

var globalPreconnectLimiter = newPreconnectLimiter(maxPreconnectedConns)

func newPreparedConnPool(limiter *preconnectLimiter) *preparedConnPool {
	return &preparedConnPool{
		changed: make(chan struct{}),
		refill:  make(chan struct{}, 1),
		limiter: limiter,
	}
}

func (p *preparedConnPool) notifyLocked() {
	close(p.changed)
	p.changed = make(chan struct{})
}

func (p *preparedConnPool) requestRefillLocked() {
	select {
	case p.refill <- struct{}{}:
	default:
	}
}

func (p *preparedConnPool) fill(ctx context.Context, count int, dial func(context.Context) (net.Conn, error), done func()) {
	if p == nil || count <= 0 || dial == nil {
		if done != nil {
			done()
		}
		return
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		if done != nil {
			done()
		}
		return
	}
	count -= len(p.ready) + p.pending
	if count <= 0 {
		p.mu.Unlock()
		if done != nil {
			done()
		}
		return
	}
	p.pending += count
	p.notifyLocked()
	p.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(count)
	for i := 0; i < count; i++ {
		go func() {
			defer wg.Done()

			release, ok := p.limiter.acquire()
			if !ok {
				p.mu.Lock()
				p.pending--
				p.notifyLocked()
				p.mu.Unlock()
				return
			}
			conn, err := dial(ctx)

			p.mu.Lock()
			p.pending--
			if err == nil && conn != nil && !p.closed {
				item := &preparedConn{
					conn:      conn,
					expiresAt: time.Now().Add(preconnectedConnTTL),
					release:   release,
				}
				p.ready = append(p.ready, item)
				p.notifyLocked()
				p.mu.Unlock()
				go p.expire(item)
				return
			}
			p.notifyLocked()
			p.mu.Unlock()

			release()
			if conn != nil {
				_ = conn.Close()
			}
		}()
	}

	if done != nil {
		go func() {
			wg.Wait()
			done()
		}()
	}
}

func (p *preparedConnPool) take(ctx context.Context) (net.Conn, bool, error) {
	if p == nil {
		return nil, false, nil
	}

	for {
		p.mu.Lock()
		if len(p.ready) > 0 {
			item := p.ready[0]
			p.ready[0] = nil
			p.ready = p.ready[1:]
			p.notifyLocked()
			p.requestRefillLocked()
			p.mu.Unlock()
			if item == nil || item.conn == nil {
				continue
			}
			if !item.expiresAt.IsZero() && !time.Now().Before(item.expiresAt) {
				item.releaseSlot()
				_ = item.conn.Close()
				continue
			}
			item.releaseSlot()
			return item.conn, true, nil
		}
		if p.pending == 0 || p.closed {
			p.mu.Unlock()
			return nil, false, nil
		}
		changed := p.changed
		p.mu.Unlock()

		select {
		case <-changed:
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}
}

func (p *preparedConnPool) waitReady(ctx context.Context, closed <-chan struct{}, count int) error {
	if p == nil || count <= 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	for {
		select {
		case <-closed:
			return net.ErrClosed
		default:
		}

		p.mu.Lock()
		if len(p.ready) >= count {
			p.mu.Unlock()
			return nil
		}
		if p.closed {
			p.mu.Unlock()
			return net.ErrClosed
		}
		changed := p.changed
		p.mu.Unlock()

		select {
		case <-changed:
		case <-closed:
			return net.ErrClosed
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (p *preparedConnPool) expire(item *preparedConn) {
	delay := time.Until(item.expiresAt)
	if delay < 0 {
		delay = 0
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	<-timer.C

	p.mu.Lock()
	for i, candidate := range p.ready {
		if candidate != item {
			continue
		}
		copy(p.ready[i:], p.ready[i+1:])
		p.ready[len(p.ready)-1] = nil
		p.ready = p.ready[:len(p.ready)-1]
		p.notifyLocked()
		p.requestRefillLocked()
		p.mu.Unlock()
		item.releaseSlot()
		_ = item.conn.Close()
		return
	}
	p.mu.Unlock()
}

func (p *preparedConnPool) close() {
	if p == nil {
		return
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	ready := p.ready
	p.ready = nil
	p.notifyLocked()
	p.mu.Unlock()

	for _, item := range ready {
		if item != nil && item.conn != nil {
			item.releaseSlot()
			_ = item.conn.Close()
		}
	}
}

type preconnectDialer struct {
	urlHost    string
	dialAddr   string
	serverName string
	tlsConfig  *tls.Config
	dial       func(context.Context, string, string) (net.Conn, error)
	pool       *preparedConnPool
}

func newPreconnectDialer(
	urlHost, dialAddr, serverName string,
	tlsConfig *tls.Config,
	dial func(context.Context, string, string) (net.Conn, error),
) *preconnectDialer {
	return &preconnectDialer{
		urlHost:    urlHost,
		dialAddr:   dialAddr,
		serverName: serverName,
		tlsConfig:  tlsConfig,
		dial:       dial,
		pool:       newPreparedConnPool(globalPreconnectLimiter),
	}
}

func (d *preconnectDialer) preconnect(ctx context.Context, tlsEnabled bool, count int) context.CancelFunc {
	if d == nil || d.pool == nil {
		return func() {}
	}

	// Auto cancels its stream probe after a successful dial. Preserve only the
	// absolute deadline while the initial pull and push connections finish.
	deadline := time.Now().Add(preconnectedConnTTL)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	dialCtx, cancel := context.WithDeadline(context.Background(), deadline)
	d.pool.fill(dialCtx, count, func(dialCtx context.Context) (net.Conn, error) {
		if tlsEnabled {
			return d.dialTLSFresh(dialCtx, "tcp", d.urlHost)
		}
		return d.dialFresh(dialCtx, "tcp", d.urlHost)
	}, cancel)
	return cancel
}

func (d *preconnectDialer) maintainPreconnect(ctx context.Context, tlsEnabled bool, count int) {
	if d == nil || d.pool == nil || count <= 0 {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	const retryInterval = 500 * time.Millisecond
	ticker := time.NewTicker(retryInterval)
	defer ticker.Stop()

	ensure := func() {
		d.pool.fill(ctx, count, func(dialCtx context.Context) (net.Conn, error) {
			if tlsEnabled {
				return d.dialTLSFresh(dialCtx, "tcp", d.urlHost)
			}
			return d.dialFresh(dialCtx, "tcp", d.urlHost)
		}, nil)
	}

	ensure()
	for {
		select {
		case <-ticker.C:
		case <-d.pool.refill:
		case <-ctx.Done():
			return
		}
		ensure()
	}
}

func (d *preconnectDialer) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d != nil && addr == d.urlHost {
		if conn, ok, err := d.pool.take(ctx); err != nil || ok {
			return conn, err
		}
	}
	return d.dialFresh(ctx, network, addr)
}

func (d *preconnectDialer) dialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d != nil && addr == d.urlHost {
		if conn, ok, err := d.pool.take(ctx); err != nil || ok {
			return conn, err
		}
	}
	return d.dialTLSFresh(ctx, network, addr)
}

func (d *preconnectDialer) dialFresh(ctx context.Context, network, addr string) (net.Conn, error) {
	if d == nil || d.dial == nil {
		return nil, errors.New("httpmask: DialContext is nil")
	}
	if addr == d.urlHost {
		addr = d.dialAddr
	}
	return d.dial(ctx, network, addr)
}

func (d *preconnectDialer) dialTLSFresh(ctx context.Context, network, addr string) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, tunnelTLSHandshakeLimit)
	defer cancel()

	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if d != nil && d.tlsConfig != nil {
		config = d.tlsConfig.Clone()
	}
	if d != nil && addr == d.urlHost {
		config.ServerName = d.serverName
	}

	rawConn, err := d.dialFresh(dialCtx, network, addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(rawConn, config)
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (d *preconnectDialer) close() {
	if d != nil {
		d.pool.close()
	}
}
