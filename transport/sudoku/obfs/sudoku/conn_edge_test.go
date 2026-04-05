package sudoku

import (
	"net"
	"testing"
)

func TestConnWrite_Empty(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	table := NewTable("edge-key", "prefer_entropy")
	conn := NewConn(c1, table, 0, 0, false)
	if n, err := conn.Write(nil); err != nil || n != 0 {
		t.Fatalf("Write(nil) = (%d, %v), want (0, nil)", n, err)
	}
	if n, err := conn.Write([]byte{}); err != nil || n != 0 {
		t.Fatalf("Write(empty) = (%d, %v), want (0, nil)", n, err)
	}
}
