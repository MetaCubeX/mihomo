package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

type captureConn struct {
	bytes.Buffer
}

func (c *captureConn) Read(_ []byte) (int, error)       { return 0, io.EOF }
func (c *captureConn) Write(p []byte) (int, error)      { return c.Buffer.Write(p) }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return nil }
func (c *captureConn) RemoteAddr() net.Addr             { return nil }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

type replayConn struct {
	reader *bytes.Reader
}

func (c *replayConn) Read(p []byte) (int, error)       { return c.reader.Read(p) }
func (c *replayConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *replayConn) Close() error                     { return nil }
func (c *replayConn) LocalAddr() net.Addr              { return nil }
func (c *replayConn) RemoteAddr() net.Addr             { return nil }
func (c *replayConn) SetDeadline(time.Time) error      { return nil }
func (c *replayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *replayConn) SetWriteDeadline(time.Time) error { return nil }

func TestRecordConn_FirstFrameUsesRandomizedCounters(t *testing.T) {
	pskSend := sha256.Sum256([]byte("record-send"))
	pskRecv := sha256.Sum256([]byte("record-recv"))

	raw := &captureConn{}
	writer, err := NewRecordConn(raw, "chacha20-poly1305", pskSend[:], pskRecv[:])
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}

	if writer.sendEpoch == 0 || writer.sendSeq == 0 {
		t.Fatalf("expected non-zero randomized counters, got epoch=%d seq=%d", writer.sendEpoch, writer.sendSeq)
	}

	want := []byte("record prefix camouflage")
	if _, err := writer.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}

	wire := raw.Bytes()
	if len(wire) < 2+recordHeaderSize {
		t.Fatalf("short frame: %d", len(wire))
	}

	bodyLen := int(binary.BigEndian.Uint16(wire[:2]))
	if bodyLen != len(wire)-2 {
		t.Fatalf("body len mismatch: got %d want %d", bodyLen, len(wire)-2)
	}

	epoch := binary.BigEndian.Uint32(wire[2:6])
	seq := binary.BigEndian.Uint64(wire[6:14])
	if epoch == 0 || seq == 0 {
		t.Fatalf("wire header still starts from zero: epoch=%d seq=%d", epoch, seq)
	}

	reader, err := NewRecordConn(&replayConn{reader: bytes.NewReader(wire)}, "chacha20-poly1305", pskRecv[:], pskSend[:])
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}

	got := make([]byte, len(want))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, want)
	}
}
