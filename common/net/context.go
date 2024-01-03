package net

import (
	"context"
	"net"
)

// SetupContextForConn is a helper function that starts connection I/O interrupter goroutine.
func SetupContextForConn(ctx context.Context, conn net.Conn) (done func(*error)) {
	var (
		quit      = make(chan struct{})
		interrupt = make(chan error, 1)
	)
	go func() {
		select {
		case <-quit:
			interrupt <- nil
		case <-ctx.Done():
			// Close the connection, discarding the error
			_ = conn.Close()
			interrupt <- ctx.Err()
		}
	}()
	return func(inputErr *error) {
		close(quit)
		if ctxErr := <-interrupt; ctxErr != nil && inputErr != nil {
			// Return context error to user.
			inputErr = &ctxErr
		}
	}
}
