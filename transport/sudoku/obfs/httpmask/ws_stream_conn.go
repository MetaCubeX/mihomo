package httpmask

import (
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

type wsStreamConn struct {
	net.Conn
	state          ws.State
	reader         *wsutil.Reader
	controlHandler wsutil.FrameHandlerFunc
}

func newWSStreamConn(conn net.Conn, state ws.State) net.Conn {
	controlHandler := wsutil.ControlFrameHandler(conn, state)
	return &wsStreamConn{
		Conn:  conn,
		state: state,
		reader: &wsutil.Reader{
			Source: conn,
			State:  state,
		},
		controlHandler: controlHandler,
	}
}

func (c *wsStreamConn) Read(b []byte) (n int, err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("websocket error: %v", v)
		}
	}()

	for {
		n, err = c.reader.Read(b)
		if errors.Is(err, io.EOF) {
			err = nil
		}
		if !errors.Is(err, wsutil.ErrNoFrameAdvance) {
			return n, err
		}

		hdr, err2 := c.reader.NextFrame()
		if err2 != nil {
			return 0, err2
		}
		if hdr.OpCode.IsControl() {
			if err := c.controlHandler(hdr, c.reader); err != nil {
				return 0, err
			}
			continue
		}
		if hdr.OpCode&(ws.OpBinary|ws.OpText) == 0 {
			if err := c.reader.Discard(); err != nil {
				return 0, err
			}
			continue
		}
	}
}

func (c *wsStreamConn) Write(b []byte) (int, error) {
	if err := wsutil.WriteMessage(c.Conn, c.state, ws.OpBinary, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *wsStreamConn) Close() error {
	_ = wsutil.WriteMessage(c.Conn, c.state, ws.OpClose, ws.NewCloseFrameBody(ws.StatusNormalClosure, ""))
	return c.Conn.Close()
}
