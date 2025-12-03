package sudoku

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/saba-futai/sudoku/apis"
	"github.com/saba-futai/sudoku/pkg/crypto"
	"github.com/saba-futai/sudoku/pkg/obfs/httpmask"
	"github.com/saba-futai/sudoku/pkg/obfs/sudoku"

	"github.com/metacubex/mihomo/log"
)

type SessionType int

const (
	SessionTypeTCP SessionType = iota
	SessionTypeUoT
)

type ServerSession struct {
	Conn   net.Conn
	Type   SessionType
	Target string
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (bc *bufferedConn) Read(p []byte) (int, error) {
	return bc.r.Read(p)
}

type preBufferedConn struct {
	net.Conn
	buf []byte
}

func (p *preBufferedConn) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	if p.Conn == nil {
		return 0, io.EOF
	}
	return p.Conn.Read(b)
}

func absInt64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// ServerHandshake performs Sudoku server-side handshake and detects UoT preface.
func ServerHandshake(rawConn net.Conn, cfg *apis.ProtocolConfig) (*ServerSession, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	handshakeTimeout := time.Duration(cfg.HandshakeTimeoutSeconds) * time.Second
	if handshakeTimeout <= 0 {
		handshakeTimeout = 5 * time.Second
	}

	bufReader := bufio.NewReader(rawConn)
	if !cfg.DisableHTTPMask {
		if peek, _ := bufReader.Peek(4); len(peek) == 4 && string(peek) == "POST" {
			if _, err := httpmask.ConsumeHeader(bufReader); err != nil {
				return nil, fmt.Errorf("invalid http header: %w", err)
			}
		}
	}

	rawConn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	bConn := &bufferedConn{
		Conn: rawConn,
		r:    bufReader,
	}
	sConn := sudoku.NewConn(bConn, cfg.Table, cfg.PaddingMin, cfg.PaddingMax, true)
	cConn, err := crypto.NewAEADConn(sConn, cfg.Key, cfg.AEADMethod)
	if err != nil {
		return nil, fmt.Errorf("crypto setup failed: %w", err)
	}

	var handshakeBuf [16]byte
	if _, err := io.ReadFull(cConn, handshakeBuf[:]); err != nil {
		cConn.Close()
		return nil, fmt.Errorf("read handshake failed: %w", err)
	}

	ts := int64(binary.BigEndian.Uint64(handshakeBuf[:8]))
	if absInt64(time.Now().Unix()-ts) > 60 {
		cConn.Close()
		return nil, fmt.Errorf("timestamp skew detected")
	}

	sConn.StopRecording()

	firstByte := make([]byte, 1)
	if _, err := io.ReadFull(cConn, firstByte); err != nil {
		cConn.Close()
		return nil, fmt.Errorf("read first byte failed: %w", err)
	}

	if firstByte[0] == UoTMagicByte {
		version := make([]byte, 1)
		if _, err := io.ReadFull(cConn, version); err != nil {
			cConn.Close()
			return nil, fmt.Errorf("read uot version failed: %w", err)
		}
		if version[0] != uotVersion {
			cConn.Close()
			return nil, fmt.Errorf("unsupported uot version: %d", version[0])
		}
		rawConn.SetReadDeadline(time.Time{})
		return &ServerSession{Conn: cConn, Type: SessionTypeUoT}, nil
	}

	prefixed := &preBufferedConn{Conn: cConn, buf: firstByte}
	target, err := decodeAddress(prefixed)
	if err != nil {
		cConn.Close()
		return nil, fmt.Errorf("read target address failed: %w", err)
	}

	rawConn.SetReadDeadline(time.Time{})
	log.Debugln("[Sudoku] incoming TCP session target: %s", target)
	return &ServerSession{
		Conn:   prefixed,
		Type:   SessionTypeTCP,
		Target: target,
	}, nil
}
