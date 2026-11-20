package net

import (
	"context"
	"net"
	"sync"

	"github.com/metacubex/mihomo/common/contextutils"
)

// SetupContextForConn is a helper function that starts connection I/O interrupter.
// if ctx be canceled before done called, it will close the connection.
// should use like this:
//
//	func streamConn(ctx context.Context, conn net.Conn) (_ net.Conn, err error) {
//		if ctx.Done() != nil {
//			done := N.SetupContextForConn(ctx, conn)
//			defer done(&err)
//		}
//		conn, err := xxx
//		return conn, err
//	}
func SetupContextForConn(ctx context.Context, conn net.Conn) (done func(*error)) {
	var stopc sync.WaitGroup
	stopc.Add(1)
	stop := contextutils.AfterFunc(ctx, func() {
		// Close the connection, discarding the error
		_ = conn.Close()
		stopc.Done()
	})
	return func(inputErr *error) {
		if !stop() {
			// The AfterFunc was started, wait for it to complete.
			stopc.Wait()
			if ctxErr := ctx.Err(); ctxErr != nil && inputErr != nil {
				// Return context error to user.
				*inputErr = ctxErr
			}
		}
	}
}

// RelayContext copies between left and right bidirectionally.
// If ctx is canceled, both connections are closed to interrupt pending I/O.
func RelayContext(ctx context.Context, leftConn, rightConn net.Conn) error {
	if ctx.Done() == nil {
		Relay(leftConn, rightConn)
		return nil
	}

	done := make(chan struct{})
	stop := contextutils.AfterFunc(ctx, func() {
		_ = leftConn.Close()
		_ = rightConn.Close()
		close(done)
	})
	Relay(leftConn, rightConn)
	if !stop() {
		<-done
		return ctx.Err()
	}
	return nil
}
