package multiplex

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/metacubex/smux"
)

const (
	// MagicByte marks a Sudoku tunnel connection that will switch into multiplex mode.
	// It is sent after the Sudoku handshake + downlink mode byte.
	MagicByte byte = 0xEF
	Version        = 0x01
)

func WritePreface(w io.Writer) error {
	_, err := w.Write([]byte{MagicByte, Version})
	return err
}

func ReadVersion(r io.Reader) (byte, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

func ValidateVersion(v byte) error {
	if v != Version {
		return fmt.Errorf("unsupported multiplex version: %d", v)
	}
	return nil
}

func defaultSmuxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.KeepAliveInterval = 15 * time.Second
	cfg.KeepAliveTimeout = 45 * time.Second
	return cfg
}

type Session struct {
	sess *smux.Session
}

func NewClientSession(conn net.Conn) (*Session, error) {
	if conn == nil {
		return nil, fmt.Errorf("nil conn")
	}
	s, err := smux.Client(conn, defaultSmuxConfig())
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &Session{sess: s}, nil
}

func NewServerSession(conn net.Conn) (*Session, error) {
	if conn == nil {
		return nil, fmt.Errorf("nil conn")
	}
	s, err := smux.Server(conn, defaultSmuxConfig())
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &Session{sess: s}, nil
}

func (s *Session) OpenStream() (net.Conn, error) {
	if s == nil || s.sess == nil {
		return nil, fmt.Errorf("nil session")
	}
	return s.sess.OpenStream()
}

func (s *Session) AcceptStream() (net.Conn, error) {
	if s == nil || s.sess == nil {
		return nil, fmt.Errorf("nil session")
	}
	return s.sess.AcceptStream()
}

func (s *Session) Close() error {
	if s == nil || s.sess == nil {
		return nil
	}
	return s.sess.Close()
}

func (s *Session) IsClosed() bool {
	if s == nil || s.sess == nil {
		return true
	}
	return s.sess.IsClosed()
}

