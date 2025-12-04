package sudoku

import (
	"bufio"
	"crypto/sha256"
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

type directionalConn struct {
	net.Conn
	reader  io.Reader
	writer  io.Writer
	closers []func() error
}

func (c *directionalConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *directionalConn) Write(p []byte) (int, error) {
	return c.writer.Write(p)
}

func (c *directionalConn) Close() error {
	var firstErr error
	for _, fn := range c.closers {
		if fn == nil {
			continue
		}
		if err := fn(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := c.Conn.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func absInt64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

const (
	downlinkModePure   byte = 0x01
	downlinkModePacked byte = 0x02
)

func downlinkMode(cfg *apis.ProtocolConfig) byte {
	if cfg.EnablePureDownlink {
		return downlinkModePure
	}
	return downlinkModePacked
}

func clientAEADSeed(key string) string {
	if recovered, err := crypto.RecoverPublicKey(key); err == nil {
		return crypto.EncodePoint(recovered)
	}
	return key
}

func buildClientObfsConn(raw net.Conn, cfg *apis.ProtocolConfig) net.Conn {
	base := sudoku.NewConn(raw, cfg.Table, cfg.PaddingMin, cfg.PaddingMax, false)
	if cfg.EnablePureDownlink {
		return base
	}
	packed := sudoku.NewPackedConn(raw, cfg.Table, cfg.PaddingMin, cfg.PaddingMax)
	return &directionalConn{
		Conn:   raw,
		reader: packed,
		writer: base,
	}
}

func buildServerObfsConn(raw net.Conn, cfg *apis.ProtocolConfig, record bool) (*sudoku.Conn, net.Conn) {
	uplink := sudoku.NewConn(raw, cfg.Table, cfg.PaddingMin, cfg.PaddingMax, record)
	if cfg.EnablePureDownlink {
		return uplink, uplink
	}
	packed := sudoku.NewPackedConn(raw, cfg.Table, cfg.PaddingMin, cfg.PaddingMax)
	return uplink, &directionalConn{
		Conn:    raw,
		reader:  uplink,
		writer:  packed,
		closers: []func() error{packed.Flush},
	}
}

func buildHandshakePayload(key string) [16]byte {
	var payload [16]byte
	binary.BigEndian.PutUint64(payload[:8], uint64(time.Now().Unix()))
	hash := sha256.Sum256([]byte(key))
	copy(payload[8:], hash[:8])
	return payload
}

// ClientHandshake performs the client-side Sudoku handshake (without sending target address).
func ClientHandshake(rawConn net.Conn, cfg *apis.ProtocolConfig) (net.Conn, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	if !cfg.DisableHTTPMask {
		if err := httpmask.WriteRandomRequestHeader(rawConn, cfg.ServerAddress); err != nil {
			return nil, fmt.Errorf("write http mask failed: %w", err)
		}
	}

	obfsConn := buildClientObfsConn(rawConn, cfg)
	cConn, err := crypto.NewAEADConn(obfsConn, clientAEADSeed(cfg.Key), cfg.AEADMethod)
	if err != nil {
		return nil, fmt.Errorf("setup crypto failed: %w", err)
	}

	handshake := buildHandshakePayload(cfg.Key)
	if _, err := cConn.Write(handshake[:]); err != nil {
		cConn.Close()
		return nil, fmt.Errorf("send handshake failed: %w", err)
	}
	if _, err := cConn.Write([]byte{downlinkMode(cfg)}); err != nil {
		cConn.Close()
		return nil, fmt.Errorf("send downlink mode failed: %w", err)
	}

	return cConn, nil
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
	sConn, obfsConn := buildServerObfsConn(bConn, cfg, true)
	cConn, err := crypto.NewAEADConn(obfsConn, cfg.Key, cfg.AEADMethod)
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

	modeBuf := []byte{0}
	if _, err := io.ReadFull(cConn, modeBuf); err != nil {
		cConn.Close()
		return nil, fmt.Errorf("read downlink mode failed: %w", err)
	}
	if modeBuf[0] != downlinkMode(cfg) {
		cConn.Close()
		return nil, fmt.Errorf("downlink mode mismatch: client=%d server=%d", modeBuf[0], downlinkMode(cfg))
	}

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
	target, err := DecodeAddress(prefixed)
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
