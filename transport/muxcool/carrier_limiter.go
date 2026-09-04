package muxcool

import (
	"net"
	"sync"
)

// CarrierLimiter enforces a shared upper bound on physical mux.cool carriers.
// A zero limit preserves the existing unlimited behavior.
type CarrierLimiter struct {
	mu      sync.Mutex
	max     int
	used    int
	changed chan struct{}
}

func NewCarrierLimiter(maxCarriers int) *CarrierLimiter {
	return &CarrierLimiter{
		max:     maxCarriers,
		changed: make(chan struct{}),
	}
}

func (l *CarrierLimiter) limited() bool {
	return l != nil && l.max > 0
}

func (l *CarrierLimiter) tryAcquire() (*carrierLease, <-chan struct{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.used >= l.max {
		return nil, l.changed
	}
	l.used++
	return &carrierLease{limiter: l}, nil
}

func (l *CarrierLimiter) release() {
	l.mu.Lock()
	l.used--
	changed := l.changed
	l.changed = make(chan struct{})
	l.mu.Unlock()
	close(changed)
}

type carrierLease struct {
	limiter *CarrierLimiter
	once    sync.Once
}

func (l *carrierLease) release() {
	if l == nil || l.limiter == nil {
		return
	}
	l.once.Do(l.limiter.release)
}

type limitedCarrier struct {
	net.Conn
	lease *carrierLease
}

func (c *limitedCarrier) Close() error {
	err := c.Conn.Close()
	c.lease.release()
	return err
}
