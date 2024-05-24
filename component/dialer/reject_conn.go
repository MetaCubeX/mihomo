package dialer

import (
	"github.com/metacubex/mihomo/common/buf"
	"io"
	"net"
	"time"
)

type NopConn struct{}

func (rw NopConn) Read(b []byte) (int, error) { return 0, io.EOF }

func (rw NopConn) ReadBuffer(buffer *buf.Buffer) error { return io.EOF }

func (rw NopConn) Write(b []byte) (int, error)          { return 0, io.EOF }
func (rw NopConn) WriteBuffer(buffer *buf.Buffer) error { return io.EOF }
func (rw NopConn) Close() error                         { return nil }
func (rw NopConn) LocalAddr() net.Addr                  { return nil }
func (rw NopConn) RemoteAddr() net.Addr                 { return nil }
func (rw NopConn) SetDeadline(time.Time) error          { return nil }
func (rw NopConn) SetReadDeadline(time.Time) error      { return nil }
func (rw NopConn) SetWriteDeadline(time.Time) error     { return nil }
