package tunnel

import (
	"net"

	C "github.com/Dreamacro/clash/constant"
)

func relayHijack(left net.Conn, right net.Conn) bool {
	var l *net.TCPConn
	var r *net.TCPConn
	var ok bool

	if l, ok = left.(*net.TCPConn); !ok {
		return false
	}

	if r, ok = right.(*net.TCPConn); !ok {
		return false
	}

	closed := make(chan struct{})

	go func() {
		defer close(closed)

		r.ReadFrom(l)
		r.Close()
	}()

	l.ReadFrom(r)
	l.Close()

	<-closed

	return true
}

func unwrap(conn net.Conn) net.Conn {
	r := conn

	for {
		w, ok := r.(C.WrappedConn)
		if !ok {
			break
		}
		rc, ok := w.RawConn()
		if !ok {
			break
		}
		r = rc
	}

	return r
}

func unwrapPacket(conn net.PacketConn) net.PacketConn {
	r := conn

	for {
		w, ok := r.(C.WrappedPacketConn)
		if !ok {
			break
		}
		rc, ok := w.RawPacketConn()
		if !ok {
			break
		}
		r = rc
	}

	return r
}
