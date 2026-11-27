package miu

import (
	"net"
	"testing"
	"time"
)

// A lane dialed to warm the pool has sent nothing, but the server's post-handshake records (session
// tickets: a REALITY server sends them after the client's Finished) can be sitting unread in its socket.
// takeIdle must not take them for a close_notify and throw the lane away; on a used lane, pending bytes
// still mean the server is closing it.
func TestTakeIdleUnusedLaneWithPendingBytes(t *testing.T) {
	for _, used := range []bool{false, true} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		accepted := make(chan net.Conn, 1)
		go func() {
			c, _ := ln.Accept()
			accepted <- c
		}()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		srv := <-accepted
		if _, err := srv.Write([]byte("post-handshake records")); err != nil {
			t.Fatal(err)
		}
		if !eventually(func() bool { _, pending := connAlive(conn); return pending }) {
			t.Fatal("the bytes never arrived")
		}
		l := newLane(conn, false, false)
		l.unauthed.Store(!used)
		l.preauthTTL = time.Minute
		c := &Client{cfg: ClientConfig{LaneIdle: time.Minute}}
		c.idle = []idleLane{{l: l, since: time.Now(), used: used}}
		got, _ := c.takeIdle(time.Now())
		switch {
		case !used && got != l:
			t.Error("an unused lane with pending session tickets was thrown away")
		case used && got != nil:
			t.Error("a used lane with pending bytes (a close_notify) was taken")
		}
		srv.Close()
		conn.Close()
		ln.Close()
	}
}
