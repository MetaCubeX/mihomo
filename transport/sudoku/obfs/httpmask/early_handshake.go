package httpmask

import (
	"net"
)

type ClientEarlyHandshake struct {
	RequestPayload []byte
	HandleResponse func(payload []byte) error
	Ready          func() bool
	WrapConn       func(raw net.Conn) (net.Conn, error)
}

type TunnelServerEarlyHandshake struct {
	Prepare func(payload []byte) (*PreparedServerEarlyHandshake, error)
}

type PreparedServerEarlyHandshake struct {
	ResponsePayload []byte
	WrapConn        func(raw net.Conn) (net.Conn, error)
	UserHash        string
}

type earlyHandshakeMeta interface {
	HTTPMaskEarlyHandshakeUserHash() string
}

type earlyHandshakeConn struct {
	net.Conn
	userHash string
}

func (c *earlyHandshakeConn) CloseWrite() error {
	if c == nil || c.Conn == nil {
		return nil
	}
	if closeWriter, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closeWriter.CloseWrite()
	}
	return nil
}

func (c *earlyHandshakeConn) CloseRead() error {
	if c == nil || c.Conn == nil {
		return nil
	}
	if closeReader, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return closeReader.CloseRead()
	}
	return nil
}

func (c *earlyHandshakeConn) HTTPMaskEarlyHandshakeUserHash() string {
	if c == nil {
		return ""
	}
	return c.userHash
}

func wrapEarlyHandshakeConn(conn net.Conn, userHash string) net.Conn {
	if conn == nil {
		return nil
	}
	return &earlyHandshakeConn{Conn: conn, userHash: userHash}
}

func EarlyHandshakeUserHash(conn net.Conn) (string, bool) {
	if conn == nil {
		return "", false
	}
	v, ok := conn.(earlyHandshakeMeta)
	if !ok {
		return "", false
	}
	return v.HTTPMaskEarlyHandshakeUserHash(), true
}

func applyEarlyHandshakeOrUpgrade(raw net.Conn, opts TunnelDialOptions) (net.Conn, error) {
	out := raw
	if opts.EarlyHandshake != nil && opts.EarlyHandshake.WrapConn != nil && (opts.EarlyHandshake.Ready == nil || opts.EarlyHandshake.Ready()) {
		wrapped, err := opts.EarlyHandshake.WrapConn(raw)
		if err != nil {
			return nil, err
		}
		if wrapped != nil {
			out = wrapped
		}
		return out, nil
	}
	if opts.Upgrade != nil {
		wrapped, err := opts.Upgrade(raw)
		if err != nil {
			return nil, err
		}
		if wrapped != nil {
			out = wrapped
		}
	}
	return out, nil
}
