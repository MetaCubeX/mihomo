package net

import (
	"context"
	"net"

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
	stopc := make(chan struct{})
	stop := contextutils.AfterFunc(ctx, func() {
		// Close the connection, discarding the error
		_ = conn.Close()
		close(stopc)
	})
	return func(inputErr *error) {
		if !stop() {
			// The AfterFunc was started, wait for it to complete.
			<-stopc
			if ctxErr := ctx.Err(); ctxErr != nil && inputErr != nil {
				// Return context error to user.
				*inputErr = ctxErr
			}
		}
	}
}
