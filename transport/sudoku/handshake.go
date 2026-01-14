package sudoku

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/metacubex/mihomo/transport/sudoku/crypto"
	"github.com/metacubex/mihomo/transport/sudoku/obfs/httpmask"
	"github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"

	"github.com/metacubex/mihomo/log"
)

type SessionType int

const (
	SessionTypeTCP SessionType = iota
	SessionTypeUoT
	SessionTypeMultiplex
)

type ServerSession struct {
	Conn   net.Conn
	Type   SessionType
	Target string

	// UserHash is a stable per-key identifier derived from the handshake payload.
	// It is primarily useful for debugging / user attribution when table rotation is enabled.
	UserHash string
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

func downlinkMode(cfg *ProtocolConfig) byte {
	if cfg.EnablePureDownlink {
		return downlinkModePure
	}
	return downlinkModePacked
}

func buildClientObfsConn(raw net.Conn, cfg *ProtocolConfig, table *sudoku.Table) net.Conn {
	baseReader := sudoku.NewConn(raw, table, cfg.PaddingMin, cfg.PaddingMax, false)
	baseWriter := newSudokuObfsWriter(raw, table, cfg.PaddingMin, cfg.PaddingMax)
	if cfg.EnablePureDownlink {
		return &directionalConn{
			Conn:   raw,
			reader: baseReader,
			writer: baseWriter,
		}
	}
	packed := sudoku.NewPackedConn(raw, table, cfg.PaddingMin, cfg.PaddingMax)
	return &directionalConn{
		Conn:   raw,
		reader: packed,
		writer: baseWriter,
	}
}

func buildServerObfsConn(raw net.Conn, cfg *ProtocolConfig, table *sudoku.Table, record bool) (*sudoku.Conn, net.Conn) {
	uplink := sudoku.NewConn(raw, table, cfg.PaddingMin, cfg.PaddingMax, record)
	if cfg.EnablePureDownlink {
		downlink := &directionalConn{
			Conn:   raw,
			reader: uplink,
			writer: newSudokuObfsWriter(raw, table, cfg.PaddingMin, cfg.PaddingMax),
		}
		return uplink, downlink
	}
	packed := sudoku.NewPackedConn(raw, table, cfg.PaddingMin, cfg.PaddingMax)
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

	// Align with upstream: only decode hex bytes when this key is an ED25519 key material.
	// For plain UUID/strings (even if they look like hex), hash the string bytes as-is.
	src := []byte(key)
	if _, err := crypto.RecoverPublicKey(key); err == nil {
		if keyBytes, decErr := hex.DecodeString(key); decErr == nil && len(keyBytes) > 0 {
			src = keyBytes
		}
	}

	hash := sha256.Sum256(src)
	copy(payload[8:], hash[:8])
	return payload
}

func NewTable(key string, tableType string) *sudoku.Table {
	table, err := NewTableWithCustom(key, tableType, "")
	if err != nil {
		panic(fmt.Sprintf("[Sudoku] failed to init tables: %v", err))
	}
	return table
}

func NewTableWithCustom(key string, tableType string, customTable string) (*sudoku.Table, error) {
	start := time.Now()
	table, err := sudoku.NewTableWithCustom(key, tableType, customTable)
	if err != nil {
		return nil, err
	}
	log.Infoln("[Sudoku] Tables initialized (%s, custom=%v) in %v", tableType, customTable != "", time.Since(start))
	return table, nil
}

func ClientAEADSeed(key string) string {
	if recovered, err := crypto.RecoverPublicKey(key); err == nil {
		return crypto.EncodePoint(recovered)
	}
	return key
}

type ClientHandshakeOptions struct {
	// HTTPMaskStrategy controls how the client generates the HTTP mask header when DisableHTTPMask=false.
	// Supported: ""/"random" (default), "post", "websocket".
	HTTPMaskStrategy string
}

// ClientHandshake performs the client-side Sudoku handshake (without sending target address).
func ClientHandshake(rawConn net.Conn, cfg *ProtocolConfig) (net.Conn, error) {
	return ClientHandshakeWithOptions(rawConn, cfg, ClientHandshakeOptions{})
}

// ClientHandshakeWithOptions performs the client-side Sudoku handshake (without sending target address).
func ClientHandshakeWithOptions(rawConn net.Conn, cfg *ProtocolConfig, opt ClientHandshakeOptions) (net.Conn, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	if !cfg.DisableHTTPMask {
		if err := WriteHTTPMaskHeader(rawConn, cfg.ServerAddress, cfg.HTTPMaskPathRoot, opt.HTTPMaskStrategy); err != nil {
			return nil, fmt.Errorf("write http mask failed: %w", err)
		}
	}

	table, err := pickClientTable(cfg)
	if err != nil {
		return nil, err
	}

	obfsConn := buildClientObfsConn(rawConn, cfg, table)
	cConn, err := crypto.NewAEADConn(obfsConn, ClientAEADSeed(cfg.Key), cfg.AEADMethod)
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
func ServerHandshake(rawConn net.Conn, cfg *ProtocolConfig) (*ServerSession, error) {
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

	rawConn.SetReadDeadline(time.Now().Add(handshakeTimeout))

	bufReader := bufio.NewReader(rawConn)
	if !cfg.DisableHTTPMask {
		if peek, err := bufReader.Peek(4); err == nil && httpmask.LooksLikeHTTPRequestStart(peek) {
			if _, err := httpmask.ConsumeHeader(bufReader); err != nil {
				return nil, fmt.Errorf("invalid http header: %w", err)
			}
		}
	}

	selectedTable, preRead, err := selectTableByProbe(bufReader, cfg, cfg.tableCandidates())
	if err != nil {
		return nil, err
	}

	baseConn := &preBufferedConn{Conn: rawConn, buf: preRead}
	bConn := &bufferedConn{Conn: baseConn, r: bufio.NewReader(baseConn)}
	sConn, obfsConn := buildServerObfsConn(bConn, cfg, selectedTable, true)
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

	userHash := userHashFromHandshake(handshakeBuf[:])
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

	if firstByte[0] == MultiplexMagicByte {
		rawConn.SetReadDeadline(time.Time{})
		return &ServerSession{Conn: cConn, Type: SessionTypeMultiplex, UserHash: userHash}, nil
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
		return &ServerSession{Conn: cConn, Type: SessionTypeUoT, UserHash: userHash}, nil
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
		Conn:     prefixed,
		Type:     SessionTypeTCP,
		Target:   target,
		UserHash: userHash,
	}, nil
}

func GenKeyPair() (privateKey, publicKey string, err error) {
	// Generate Master Key
	pair, err := crypto.GenerateMasterKey()
	if err != nil {
		return
	}
	// Split the master private key to get Available Private Key
	availablePrivateKey, err := crypto.SplitPrivateKey(pair.Private)
	if err != nil {
		return
	}
	privateKey = availablePrivateKey            // Available Private Key for client
	publicKey = crypto.EncodePoint(pair.Public) // Master Public Key for server
	return
}

func normalizeHTTPMaskStrategy(strategy string) string {
	s := strings.TrimSpace(strings.ToLower(strategy))
	switch s {
	case "", "random":
		return "random"
	case "ws":
		return "websocket"
	default:
		return s
	}
}

func userHashFromHandshake(handshakeBuf []byte) string {
	if len(handshakeBuf) < 16 {
		return ""
	}
	return hex.EncodeToString(handshakeBuf[8:16])
}
