package net

import (
	"context"
	"net"
	"sync"
)

type handleContextListener struct {
	net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	conns    chan net.Conn
	err      error
	once     sync.Once
	handle   func(context.Context, net.Conn) (net.Conn, error)
	panicLog func(any)
}

func (l *handleContextListener) init() {
	go func() {
		for {
			c, err := l.Listener.Accept()
			if err != nil {
				l.err = err
				close(l.conns)
				return
			}
			go func() {
				defer func() {
					if r := recover(); r != nil {
						if l.panicLog != nil {
							l.panicLog(r)
						}
					}
				}()
				if conn, err := l.handle(l.ctx, c); err == nil {
					l.conns <- conn
				} else {
					// handle failed, close the underlying connection.
					_ = c.Close()
				}
			}()
		}
	}()
}

func (l *handleContextListener) Accept() (net.Conn, error) {
	l.once.Do(l.init)
	if c, ok := <-l.conns; ok {
		return c, nil
	}
	return nil, l.err
}

func (l *handleContextListener) Close() error {
	l.cancel()
	l.once.Do(func() { // l.init has not been called yet, so close related resources directly.
		l.err = net.ErrClosed
		close(l.conns)
	})
	defer func() {
		// at here, listener has been closed, so we should close all connections in the channel
		for c := range l.conns {
			go func(c net.Conn) {
				defer func() {
					if r := recover(); r != nil {
						if l.panicLog != nil {
							l.panicLog(r)
						}
					}
				}()
				_ = c.Close()
			}(c)
		}
	}()
	return l.Listener.Close()
}

func NewHandleContextListener(ctx context.Context, l net.Listener, handle func(context.Context, net.Conn) (net.Conn, error), panicLog func(any)) net.Listener {
	ctx, cancel := context.WithCancel(ctx)
	return &handleContextListener{
		Listener: l,
		ctx:      ctx,
		cancel:   cancel,
		conns:    make(chan net.Conn),
		handle:   handle,
		panicLog: panicLog,
	}
}
