package muxcool

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

const (
	DefaultMaxConcurrency      = 8
	DefaultMaxConnections      = 128
	DefaultFirstPayloadTimeout = 100 * time.Millisecond
	DefaultIdleTimeout         = 16 * time.Second
)

var ErrPoolClosed = errors.New("mux.cool pool is closed")

type Timer interface {
	Stop() bool
}

type CarrierDialer func(context.Context) (net.Conn, error)

type Options struct {
	MaxConcurrency      int
	MaxConnections      int
	CarrierLimiter      *CarrierLimiter
	FirstPayloadTimeout time.Duration
	IdleTimeout         time.Duration
	AfterFunc           func(time.Duration, func()) Timer
}

type Pool struct {
	dial    CarrierDialer
	options Options

	mu         sync.Mutex
	workers    []*carrierWorker
	idle       map[*carrierWorker]Timer
	dialing    chan struct{}
	dialCancel context.CancelFunc
	changed    chan struct{}
	done       chan struct{}
	closed     bool
	closeOnce  sync.Once
}

func NewPool(dial CarrierDialer, options Options) *Pool {
	if options.MaxConcurrency == 0 {
		options.MaxConcurrency = DefaultMaxConcurrency
	}
	if options.MaxConnections == 0 {
		options.MaxConnections = DefaultMaxConnections
	}
	if options.FirstPayloadTimeout == 0 {
		options.FirstPayloadTimeout = DefaultFirstPayloadTimeout
	}
	if options.IdleTimeout == 0 {
		options.IdleTimeout = DefaultIdleTimeout
	}
	if options.AfterFunc == nil {
		options.AfterFunc = func(duration time.Duration, fn func()) Timer {
			return time.AfterFunc(duration, fn)
		}
	}
	return &Pool{
		dial:    dial,
		options: options,
		idle:    make(map[*carrierWorker]Timer),
		changed: make(chan struct{}),
		done:    make(chan struct{}),
	}
}

func (p *Pool) DialContext(ctx context.Context, destination string, port uint16) (net.Conn, error) {
	opened, err := p.openContext(ctx, destination, port, [8]byte{}, false)
	if err != nil {
		return nil, err
	}
	return opened.stream, nil
}

func (p *Pool) ListenPacketContext(ctx context.Context, destination string, port uint16, globalID [8]byte) (net.PacketConn, error) {
	opened, err := p.openContext(ctx, destination, port, globalID, true)
	if err != nil {
		return nil, err
	}
	return opened.packet, nil
}

type openedSession struct {
	stream net.Conn
	packet net.PacketConn
}

func (p *Pool) openContext(
	ctx context.Context,
	destination string,
	port uint16,
	globalID [8]byte,
	packet bool,
) (openedSession, error) {
	for {
		if err := context.Cause(ctx); err != nil {
			return openedSession{}, err
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return openedSession{}, ErrPoolClosed
		}

		for _, worker := range p.workers {
			conn, err := openWorkerSession(worker, ctx, destination, port, globalID, packet, p.options.FirstPayloadTimeout)
			if err != nil {
				continue
			}
			p.stopIdleLocked(worker)
			p.mu.Unlock()
			return conn, nil
		}

		if dialing := p.dialing; dialing != nil {
			done := p.done
			p.mu.Unlock()
			select {
			case <-dialing:
				continue
			case <-done:
				return openedSession{}, ErrPoolClosed
			case <-ctx.Done():
				return openedSession{}, context.Cause(ctx)
			}
		}

		var lease *carrierLease
		if p.options.CarrierLimiter.limited() {
			var capacityWait <-chan struct{}
			lease, capacityWait = p.options.CarrierLimiter.tryAcquire()
			if lease == nil {
				changed := p.changed
				done := p.done
				p.mu.Unlock()
				select {
				case <-changed:
					continue
				case <-capacityWait:
					continue
				case <-done:
					return openedSession{}, ErrPoolClosed
				case <-ctx.Done():
					return openedSession{}, context.Cause(ctx)
				}
			}
		}

		dialing := make(chan struct{})
		dialCtx, cancel := context.WithCancel(ctx)
		p.dialing = dialing
		p.dialCancel = cancel
		p.mu.Unlock()

		carrier, err := p.dial(dialCtx)
		cancel()
		if err != nil {
			if carrier != nil {
				_ = carrier.Close()
			}
			lease.release()
		} else if lease != nil {
			carrier = &limitedCarrier{Conn: carrier, lease: lease}
		}

		p.mu.Lock()
		if p.dialing == dialing {
			p.dialing = nil
			p.dialCancel = nil
			close(dialing)
		}
		if p.closed {
			p.mu.Unlock()
			if carrier != nil {
				_ = carrier.Close()
			}
			return openedSession{}, ErrPoolClosed
		}
		if err != nil {
			p.mu.Unlock()
			return openedSession{}, err
		}

		worker := newCarrierWorker(carrier, p.options.MaxConcurrency, p.options.MaxConnections, p.removeWorker)
		worker.onIdle = p.scheduleIdle
		if p.options.CarrierLimiter.limited() {
			worker.onAvailable = p.signalAvailable
		}
		p.workers = append(p.workers, worker)
		conn, err := openWorkerSession(worker, ctx, destination, port, globalID, packet, p.options.FirstPayloadTimeout)
		if err == nil {
			p.mu.Unlock()
			return conn, nil
		}
		p.removeWorkerLocked(worker)
		p.mu.Unlock()
		worker.close(err)
		return openedSession{}, err
	}
}

func (p *Pool) signalAvailable(*carrierWorker) {
	p.mu.Lock()
	p.signalChangedLocked()
	p.mu.Unlock()
}

func (p *Pool) signalChangedLocked() {
	changed := p.changed
	p.changed = make(chan struct{})
	close(changed)
}

func openWorkerSession(
	worker *carrierWorker,
	ctx context.Context,
	destination string,
	port uint16,
	globalID [8]byte,
	packet bool,
	firstPayloadTimeout time.Duration,
) (openedSession, error) {
	if packet {
		connection, err := worker.openPacketSession(destination, port, globalID)
		return openedSession{packet: connection}, err
	}
	connection, err := worker.openSession(ctx, destination, port, firstPayloadTimeout)
	return openedSession{stream: connection}, err
}

func (p *Pool) scheduleIdle(worker *carrierWorker) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || !p.containsWorkerLocked(worker) || worker.activeSessions() != 0 {
		return
	}
	p.stopIdleLocked(worker)
	p.idle[worker] = p.options.AfterFunc(p.options.IdleTimeout, func() {
		p.closeIfIdle(worker)
	})
}

func (p *Pool) closeIfIdle(worker *carrierWorker) {
	p.mu.Lock()
	if p.closed || !p.containsWorkerLocked(worker) || worker.activeSessions() != 0 {
		p.mu.Unlock()
		return
	}
	p.removeWorkerLocked(worker)
	p.mu.Unlock()
	worker.close(nil)
}

func (p *Pool) stopIdleLocked(worker *carrierWorker) {
	if timer := p.idle[worker]; timer != nil {
		timer.Stop()
		delete(p.idle, worker)
	}
}

func (p *Pool) removeWorker(worker *carrierWorker) {
	p.mu.Lock()
	p.removeWorkerLocked(worker)
	p.mu.Unlock()
}

func (p *Pool) removeWorkerLocked(worker *carrierWorker) {
	p.stopIdleLocked(worker)
	for index, candidate := range p.workers {
		if candidate == worker {
			p.workers = append(p.workers[:index], p.workers[index+1:]...)
			return
		}
	}
}

func (p *Pool) containsWorkerLocked(worker *carrierWorker) bool {
	for _, candidate := range p.workers {
		if candidate == worker {
			return true
		}
	}
	return false
}

func (p *Pool) activeSessions() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	total := 0
	for _, worker := range p.workers {
		total += worker.activeSessions()
	}
	return total
}

func (p *Pool) workerCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.workers)
}

func (p *Pool) Close() error {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		close(p.done)
		dialCancel := p.dialCancel
		workers := append([]*carrierWorker(nil), p.workers...)
		p.workers = nil
		for worker := range p.idle {
			p.stopIdleLocked(worker)
		}
		p.mu.Unlock()
		if dialCancel != nil {
			dialCancel()
		}
		for _, worker := range workers {
			worker.close(ErrPoolClosed)
		}
	})
	return nil
}
