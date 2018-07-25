package tunnel

import (
	"net"

	C "github.com/Dreamacro/clash/constant"
)

// TrafficTrack record traffic of net.Conn
type TrafficTrack struct {
	net.Conn
	traffic *C.Traffic
}

func (tt *TrafficTrack) Read(b []byte) (int, error) {
	n, err := tt.Conn.Read(b)
	tt.traffic.Down() <- int64(n)
	return n, err
}

func (tt *TrafficTrack) Write(b []byte) (int, error) {
	n, err := tt.Conn.Write(b)
	tt.traffic.Up() <- int64(n)
	return n, err
}

func newTrafficTrack(conn net.Conn, traffic *C.Traffic) *TrafficTrack {
	return &TrafficTrack{traffic: traffic, Conn: conn}
}
