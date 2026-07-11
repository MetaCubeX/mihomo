package sudoku

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"
)

type MultiplexBaseDialer func(context.Context) (net.Conn, error)

// MultiplexDialer starts maintaining a warmed Sudoku mux session after the
// first successful Dial and recreates it after transport failures.
// Concurrent callers share the same creation attempt.
type MultiplexDialer struct {
	dialBase MultiplexBaseDialer

	mu           sync.Mutex
	creating     bool
	createDone   chan struct{}
	createStop   context.CancelFunc
	client       *MultiplexClient
	maintainStop context.CancelFunc
	maintainDone chan struct{}
	closed       bool
}

func NewMultiplexDialer(dialBase MultiplexBaseDialer) (*MultiplexDialer, error) {
	if dialBase == nil {
		return nil, fmt.Errorf("nil multiplex base dialer")
	}
	return &MultiplexDialer{dialBase: dialBase}, nil
}

func (d *MultiplexDialer) Dial(ctx context.Context, targetAddress string) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		client, err := d.getOrCreateClient(ctx)
		if err != nil {
			return nil, err
		}
		stream, err := client.Dial(ctx, targetAddress)
		if err == nil {
			d.startMaintaining()
			return stream, nil
		}
		if !client.IsClosed() {
			return nil, err
		}
		lastErr = err
		d.discardClient(client)
	}
	return nil, fmt.Errorf("multiplex open stream failed: %w", lastErr)
}

// Maintain keeps a ready mux session available until ctx is canceled.
func (d *MultiplexDialer) Maintain(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}

	const (
		minBackoff = 250 * time.Millisecond
		maxBackoff = 5 * time.Second
	)
	backoff := minBackoff
	for {
		client, err := d.getOrCreateClient(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || !waitMultiplexRetry(ctx, backoff) {
				return
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		backoff = minBackoff
		select {
		case <-ctx.Done():
			return
		case <-client.Done():
		}
		d.discardClient(client)
		if ctx.Err() != nil || !waitMultiplexRetry(ctx, backoff) {
			return
		}
	}
}

func (d *MultiplexDialer) Close() error {
	if d == nil {
		return nil
	}

	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	stop := d.createStop
	client := d.client
	d.client = nil
	stopMaintaining := d.maintainStop
	maintainDone := d.maintainDone
	d.mu.Unlock()

	if stopMaintaining != nil {
		stopMaintaining()
	}
	if stop != nil {
		stop()
	}
	var err error
	if client != nil {
		err = client.Close()
	}
	if maintainDone != nil {
		<-maintainDone
	}
	return err
}

func (d *MultiplexDialer) startMaintaining() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.maintainDone != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	d.maintainStop = cancel
	d.maintainDone = done
	go func() {
		defer close(done)
		d.Maintain(ctx)
	}()
}

func (d *MultiplexDialer) getOrCreateClient(ctx context.Context) (*MultiplexClient, error) {
	if d == nil {
		return nil, net.ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}

	for {
		d.mu.Lock()
		if d.closed {
			d.mu.Unlock()
			return nil, net.ErrClosed
		}
		if client := d.client; client != nil && !client.IsClosed() {
			d.mu.Unlock()
			return client, nil
		}
		if d.creating {
			done := d.createDone
			d.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		d.creating = true
		d.createDone = make(chan struct{})
		d.mu.Unlock()
		break
	}

	createCtx, stop := context.WithCancel(ctx)
	d.mu.Lock()
	if d.closed {
		d.finishCreateLocked()
		d.mu.Unlock()
		stop()
		return nil, net.ErrClosed
	}
	d.createStop = stop
	d.mu.Unlock()

	client, err := d.createClient(createCtx)
	stop()

	d.mu.Lock()
	d.createStop = nil
	if err == nil && !d.closed {
		d.client = client
	} else if client != nil {
		_ = client.Close()
	}
	d.finishCreateLocked()
	closed := d.closed
	d.mu.Unlock()

	if closed {
		return nil, net.ErrClosed
	}
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (d *MultiplexDialer) createClient(ctx context.Context) (*MultiplexClient, error) {
	baseConn, err := d.dialBase(ctx)
	if err != nil {
		return nil, err
	}

	stop := contextutils.AfterFunc(ctx, func() {
		_ = baseConn.Close()
	})
	client, err := StartMultiplexClient(ctx, baseConn)
	if err != nil {
		stop()
		_ = baseConn.Close()
		return nil, err
	}
	if !stop() {
		_ = client.Close()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, net.ErrClosed
	}
	return client, nil
}

func (d *MultiplexDialer) finishCreateLocked() {
	d.creating = false
	if d.createDone != nil {
		close(d.createDone)
		d.createDone = nil
	}
}

func (d *MultiplexDialer) discardClient(client *MultiplexClient) {
	if d == nil || client == nil {
		return
	}
	d.mu.Lock()
	if d.client == client {
		d.client = nil
	}
	d.mu.Unlock()
}

func waitMultiplexRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

var _ io.Closer = (*MultiplexDialer)(nil)
