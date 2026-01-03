package sudoku

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/metacubex/mihomo/transport/sudoku/multiplex"
)

const (
	MultiplexMagicByte byte = multiplex.MagicByte
	MultiplexVersion   byte = multiplex.Version
)

// StartMultiplexClient writes the multiplex preface and upgrades an already-handshaked Sudoku tunnel into a multiplex session.
func StartMultiplexClient(conn net.Conn) (*MultiplexClient, error) {
	if conn == nil {
		return nil, fmt.Errorf("nil conn")
	}

	if err := multiplex.WritePreface(conn); err != nil {
		return nil, fmt.Errorf("write multiplex preface failed: %w", err)
	}

	sess, err := multiplex.NewClientSession(conn)
	if err != nil {
		return nil, fmt.Errorf("start multiplex session failed: %w", err)
	}

	return &MultiplexClient{sess: sess}, nil
}

type MultiplexClient struct {
	sess *multiplex.Session
}

// Dial opens a new logical stream, writes the target address, and returns the stream as net.Conn.
func (c *MultiplexClient) Dial(ctx context.Context, targetAddress string) (net.Conn, error) {
	if c == nil || c.sess == nil || c.sess.IsClosed() {
		return nil, fmt.Errorf("multiplex session is closed")
	}
	if strings.TrimSpace(targetAddress) == "" {
		return nil, fmt.Errorf("target address cannot be empty")
	}

	stream, err := c.sess.OpenStream()
	if err != nil {
		return nil, err
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetWriteDeadline(deadline)
		defer stream.SetWriteDeadline(time.Time{})
	}

	addrBuf, err := EncodeAddress(targetAddress)
	if err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("encode target address failed: %w", err)
	}
	if _, err := stream.Write(addrBuf); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("send target address failed: %w", err)
	}

	return stream, nil
}

func (c *MultiplexClient) Close() error {
	if c == nil || c.sess == nil {
		return nil
	}
	return c.sess.Close()
}

func (c *MultiplexClient) IsClosed() bool {
	if c == nil || c.sess == nil {
		return true
	}
	return c.sess.IsClosed()
}

// AcceptMultiplexServer upgrades a server-side, already-handshaked Sudoku connection into a multiplex session.
//
// The caller must have already consumed the multiplex magic byte (MultiplexMagicByte). This function consumes the
// multiplex version byte and starts the session.
func AcceptMultiplexServer(conn net.Conn) (*MultiplexServer, error) {
	if conn == nil {
		return nil, fmt.Errorf("nil conn")
	}
	v, err := multiplex.ReadVersion(conn)
	if err != nil {
		return nil, err
	}
	if err := multiplex.ValidateVersion(v); err != nil {
		return nil, err
	}
	sess, err := multiplex.NewServerSession(conn)
	if err != nil {
		return nil, err
	}
	return &MultiplexServer{sess: sess}, nil
}

// MultiplexServer wraps a multiplex session created from a handshaked Sudoku tunnel connection.
type MultiplexServer struct {
	sess *multiplex.Session
}

func (s *MultiplexServer) AcceptStream() (net.Conn, error) {
	if s == nil || s.sess == nil {
		return nil, fmt.Errorf("nil session")
	}
	return s.sess.AcceptStream()
}

// AcceptTCP accepts a multiplex stream and reads the target address preface, returning the stream positioned at
// application data.
func (s *MultiplexServer) AcceptTCP() (net.Conn, string, error) {
	stream, err := s.AcceptStream()
	if err != nil {
		return nil, "", err
	}

	target, err := DecodeAddress(stream)
	if err != nil {
		_ = stream.Close()
		return nil, "", err
	}

	return stream, target, nil
}

func (s *MultiplexServer) Close() error {
	if s == nil || s.sess == nil {
		return nil
	}
	return s.sess.Close()
}

func (s *MultiplexServer) IsClosed() bool {
	if s == nil || s.sess == nil {
		return true
	}
	return s.sess.IsClosed()
}

