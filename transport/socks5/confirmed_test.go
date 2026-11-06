package socks5

import (
	"bytes"
	"errors"
	"testing"
)

type handshakeBuffer struct {
	*bytes.Reader
	writes bytes.Buffer
}

func (b *handshakeBuffer) Write(p []byte) (int, error) { return b.writes.Write(p) }
func TestConfirmedReplyAndLegacyIsolation(t *testing.T) {
	for _, rep := range []byte{0, 1, 3, 4, 5, 6, 7, 8} {
		reply := append([]byte{5, 0, 5, rep, 0, 1}, make([]byte, 6)...)
		makeBuffer := func() *handshakeBuffer { return &handshakeBuffer{Reader: bytes.NewReader(reply)} }
		addr := ParseAddr("192.0.2.2:443")
		_, legacy := ClientHandshake(makeBuffer(), addr, CmdConnect, nil)
		if legacy != nil {
			t.Fatalf("legacy path changed: %v", legacy)
		}
		_, strict := ClientHandshakeConfirmed(makeBuffer(), addr, CmdConnect, nil)
		if rep == 0 && strict != nil {
			t.Fatal(strict)
		}
		if rep != 0 && !errors.Is(strict, Error(rep)) {
			t.Fatalf("reply %d was accepted: %v", rep, strict)
		}
	}
	for _, hdr := range [][]byte{{4, 0, 0}, {5, 0, 1}} {
		reply := append([]byte{5, 0}, hdr...)
		reply = append(reply, append([]byte{1}, make([]byte, 6)...)...)
		_, err := ClientHandshakeConfirmed(&handshakeBuffer{Reader: bytes.NewReader(reply)}, ParseAddr("192.0.2.2:443"), CmdConnect, nil)
		if err == nil {
			t.Fatal("malformed reply accepted")
		}
	}
}
