package main

import (
	"context"
	"net"
	"time"
)

func Listen(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{}

	var lastErr error
	for i := 0; i < 5; i++ {
		l, err := lc.Listen(context.Background(), network, address)
		if err == nil {
			return l, nil
		}

		lastErr = err
		time.Sleep(time.Millisecond * 200)
	}
	return nil, lastErr
}

func ListenPacket(network, address string) (net.PacketConn, error) {
	var lastErr error
	for i := 0; i < 5; i++ {
		l, err := net.ListenPacket(network, address)
		if err == nil {
			return l, nil
		}

		lastErr = err
		time.Sleep(time.Millisecond * 200)
	}
	return nil, lastErr
}

func TCPing(addr string) bool {
	for i := 0; i < 10; i++ {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(time.Millisecond * 500)
	}

	return false
}
