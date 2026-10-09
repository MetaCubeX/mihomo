package nowhere

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

type uotReadStep struct {
	data []byte
	err  error
}

type scriptedUOTConn struct {
	net.Conn
	steps []uotReadStep
}

func (c *scriptedUOTConn) Read(b []byte) (int, error) {
	if len(c.steps) == 0 {
		return 0, io.EOF
	}
	s := &c.steps[0]
	n := copy(b, s.data)
	s.data = s.data[n:]
	if len(s.data) != 0 {
		return n, nil
	}
	err := s.err
	c.steps = c.steps[1:]
	return n, err
}

func TestUOTReadDeadlineRecovery(t *testing.T) {
	wire := []byte{0, 5, 1, 2, 3, 4, 5}
	for _, cut := range []int{0, 1, 2, 3, 6} {
		for _, size := range []int{0, 2, 5} {
			t.Run(fmt.Sprintf("cut=%d/buffer=%d", cut, size), func(t *testing.T) {
				a, b := net.Pipe()
				defer b.Close()
				next := cut
				if next < len(wire)-1 {
					next++
				}
				c := &scriptedUOTConn{Conn: a, steps: []uotReadStep{
					{wire[:cut], nil},
					{nil, os.ErrDeadlineExceeded},
					{wire[cut:next], nil},
					{nil, os.ErrDeadlineExceeded},
					{append(append([]byte(nil), wire[next:]...), 0, 1, 42, 0, 0), nil},
				}}
				l := &lane{Conn: c}
				p, err := newPacket(&flowConn{reader: l, writer: l}, 1, "127.0.0.1:53", nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				for i := 0; i < 2; i++ {
					buf := make([]byte, 8)
					if n, _, err := p.ReadFrom(buf); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
						t.Fatalf("timeout %d: n=%d err=%v", i, n, err)
					}
					// A timed-out read must not retain the caller's buffer.
					for i := range buf {
						buf[i] = 255
					}
					_ = p.SetReadDeadline(time.Time{})
				}
				buf := make([]byte, size)
				n, addr, err := p.ReadFrom(buf)
				var wantErr error
				if size < 5 {
					wantErr = io.ErrShortBuffer
				}
				if n != size || !errors.Is(err, wantErr) || addr.String() != "127.0.0.1:53" || !bytes.Equal(buf, wire[2:2+size]) {
					t.Fatalf("resumed packet: n=%d addr=%v err=%v data=%x", n, addr, err, buf)
				}
				for _, want := range [][]byte{{42}, {}} {
					buf := make([]byte, 8)
					n, _, err := p.ReadFrom(buf)
					if err != nil || !bytes.Equal(buf[:n], want) {
						t.Fatalf("next packet: n=%d err=%v data=%x", n, err, buf[:n])
					}
				}
				if _, _, err := p.ReadFrom(make([]byte, 8)); !errors.Is(err, io.EOF) {
					t.Fatalf("clean EOF: %v", err)
				}
			})
		}
	}
}

func TestUOTCloseUnblocksRead(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	l := &lane{Conn: a}
	p, err := newPacket(&flowConn{reader: l, writer: l}, 1, "127.0.0.1:53", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	done := make(chan error, 1)
	go func() { _, _, err := p.ReadFrom(make([]byte, 8)); done <- err }()
	// Ensure a read owns the read mutex and is waiting inside a frame.
	_ = b.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if err := writeFull(b, []byte{0}); err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { p.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close deadlocked with a partial UoT read")
	}
	if err := <-done; err == nil {
		t.Fatal("closed read succeeded")
	}
}
