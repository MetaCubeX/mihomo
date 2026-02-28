package sudoku

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/metacubex/mihomo/transport/sudoku/crypto"
	"github.com/metacubex/mihomo/transport/sudoku/obfs/httpmask"
	"github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
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

	// UserHash is a stable per-key identifier derived from the client hello payload.
	UserHash string
}

type HandshakeMeta struct {
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

func newDirectionalConn(base net.Conn, reader io.Reader, writer io.Writer, closers ...func() error) net.Conn {
	return &directionalConn{
		Conn:    base,
		reader:  reader,
		writer:  writer,
		closers: closers,
	}
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

func buildClientObfsConn(raw net.Conn, cfg *ProtocolConfig, table *sudoku.Table) net.Conn {
	baseSudoku := sudoku.NewConn(raw, table, cfg.PaddingMin, cfg.PaddingMax, false)
	if cfg.EnablePureDownlink {
		return baseSudoku
	}
	packed := sudoku.NewPackedConn(raw, table, cfg.PaddingMin, cfg.PaddingMax)
	return newDirectionalConn(raw, packed, baseSudoku)
}

func buildServerObfsConn(raw net.Conn, cfg *ProtocolConfig, table *sudoku.Table, record bool) (*sudoku.Conn, net.Conn) {
	uplinkSudoku := sudoku.NewConn(raw, table, cfg.PaddingMin, cfg.PaddingMax, record)
	if cfg.EnablePureDownlink {
		return uplinkSudoku, uplinkSudoku
	}
	packed := sudoku.NewPackedConn(raw, table, cfg.PaddingMin, cfg.PaddingMax)
	return uplinkSudoku, newDirectionalConn(raw, uplinkSudoku, packed, packed.Flush)
}

func isLegacyHTTPMaskMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "legacy":
		return true
	default:
		return false
	}
}

// ClientHandshake performs the client-side Sudoku handshake (no target request).
func ClientHandshake(rawConn net.Conn, cfg *ProtocolConfig) (net.Conn, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	if !cfg.DisableHTTPMask && isLegacyHTTPMaskMode(cfg.HTTPMaskMode) {
		if err := httpmask.WriteRandomRequestHeaderWithPathRoot(rawConn, cfg.ServerAddress, cfg.HTTPMaskPathRoot); err != nil {
			return nil, fmt.Errorf("write http mask failed: %w", err)
		}
	}

	table, err := pickClientTable(cfg)
	if err != nil {
		return nil, err
	}

	seed := ClientAEADSeed(cfg.Key)
	obfsConn := buildClientObfsConn(rawConn, cfg, table)
	pskC2S, pskS2C := derivePSKDirectionalBases(seed)
	rc, err := crypto.NewRecordConn(obfsConn, cfg.AEADMethod, pskC2S, pskS2C)
	if err != nil {
		return nil, fmt.Errorf("setup crypto failed: %w", err)
	}

	if _, err := kipHandshakeClient(rc, seed, kipUserHashFromKey(cfg.Key), KIPFeatAll); err != nil {
		_ = rc.Close()
		return nil, err
	}

	return rc, nil
}

func readFirstSessionMessage(conn net.Conn) (*KIPMessage, error) {
	for {
		msg, err := ReadKIPMessage(conn)
		if err != nil {
			return nil, err
		}
		if msg.Type == KIPTypeKeepAlive {
			continue
		}
		return msg, nil
	}
}

// ServerHandshake performs the server-side KIP handshake.
func ServerHandshake(rawConn net.Conn, cfg *ProtocolConfig) (net.Conn, *HandshakeMeta, error) {
	if cfg == nil {
		return nil, nil, fmt.Errorf("config is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid config: %w", err)
	}

	handshakeTimeout := time.Duration(cfg.HandshakeTimeoutSeconds) * time.Second
	if handshakeTimeout <= 0 {
		handshakeTimeout = 5 * time.Second
	}

	_ = rawConn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	defer func() { _ = rawConn.SetReadDeadline(time.Time{}) }()

	bufReader := bufio.NewReader(rawConn)
	if !cfg.DisableHTTPMask && isLegacyHTTPMaskMode(cfg.HTTPMaskMode) {
		if peek, err := bufReader.Peek(4); err == nil && httpmask.LooksLikeHTTPRequestStart(peek) {
			if _, err := httpmask.ConsumeHeader(bufReader); err != nil {
				return nil, nil, fmt.Errorf("invalid http header: %w", err)
			}
		}
	}

	selectedTable, preRead, err := selectTableByProbe(bufReader, cfg, cfg.tableCandidates())
	if err != nil {
		return nil, nil, err
	}

	baseConn := &preBufferedConn{Conn: rawConn, buf: preRead}
	bConn := &bufferedConn{Conn: baseConn, r: bufio.NewReader(baseConn)}
	sConn, obfsConn := buildServerObfsConn(bConn, cfg, selectedTable, true)

	seed := ClientAEADSeed(cfg.Key)
	pskC2S, pskS2C := derivePSKDirectionalBases(seed)
	// Server side: recv is client->server, send is server->client.
	rc, err := crypto.NewRecordConn(obfsConn, cfg.AEADMethod, pskS2C, pskC2S)
	if err != nil {
		return nil, nil, fmt.Errorf("setup crypto failed: %w", err)
	}

	msg, err := ReadKIPMessage(rc)
	if err != nil {
		_ = rc.Close()
		return nil, nil, fmt.Errorf("handshake read failed: %w", err)
	}
	if msg.Type != KIPTypeClientHello {
		_ = rc.Close()
		return nil, nil, fmt.Errorf("unexpected handshake message: %d", msg.Type)
	}
	ch, err := DecodeKIPClientHelloPayload(msg.Payload)
	if err != nil {
		_ = rc.Close()
		return nil, nil, fmt.Errorf("decode client hello failed: %w", err)
	}
	if absInt64(time.Now().Unix()-ch.Timestamp.Unix()) > int64(kipHandshakeSkew.Seconds()) {
		_ = rc.Close()
		return nil, nil, fmt.Errorf("time skew/replay")
	}

	userHashHex := hex.EncodeToString(ch.UserHash[:])
	if !globalHandshakeReplay.allow(userHashHex, ch.Nonce, time.Now()) {
		_ = rc.Close()
		return nil, nil, fmt.Errorf("replay")
	}

	curve := ecdh.X25519()
	serverEphemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		_ = rc.Close()
		return nil, nil, fmt.Errorf("ecdh generate failed: %w", err)
	}
	shared, err := x25519SharedSecret(serverEphemeral, ch.ClientPub[:])
	if err != nil {
		_ = rc.Close()
		return nil, nil, fmt.Errorf("ecdh failed: %w", err)
	}
	sessC2S, sessS2C, err := deriveSessionDirectionalBases(seed, shared, ch.Nonce)
	if err != nil {
		_ = rc.Close()
		return nil, nil, fmt.Errorf("derive session keys failed: %w", err)
	}

	var serverPub [kipHelloPubSize]byte
	copy(serverPub[:], serverEphemeral.PublicKey().Bytes())
	sh := &KIPServerHello{
		Nonce:         ch.Nonce,
		ServerPub:     serverPub,
		SelectedFeats: ch.Features & KIPFeatAll,
	}
	if err := WriteKIPMessage(rc, KIPTypeServerHello, sh.EncodePayload()); err != nil {
		_ = rc.Close()
		return nil, nil, fmt.Errorf("write server hello failed: %w", err)
	}
	if err := rc.Rekey(sessS2C, sessC2S); err != nil {
		_ = rc.Close()
		return nil, nil, fmt.Errorf("rekey failed: %w", err)
	}

	sConn.StopRecording()

	return rc, &HandshakeMeta{UserHash: userHashHex}, nil
}

// ReadServerSession consumes the first post-handshake KIP control message and returns the session intent.
func ReadServerSession(conn net.Conn, meta *HandshakeMeta) (*ServerSession, error) {
	if conn == nil {
		return nil, fmt.Errorf("nil conn")
	}
	userHash := ""
	if meta != nil {
		userHash = meta.UserHash
	}

	first, err := readFirstSessionMessage(conn)
	if err != nil {
		return nil, err
	}

	switch first.Type {
	case KIPTypeStartUoT:
		return &ServerSession{Conn: conn, Type: SessionTypeUoT, UserHash: userHash}, nil
	case KIPTypeStartMux:
		return &ServerSession{Conn: conn, Type: SessionTypeMultiplex, UserHash: userHash}, nil
	case KIPTypeOpenTCP:
		target, err := DecodeAddress(bytes.NewReader(first.Payload))
		if err != nil {
			return nil, fmt.Errorf("decode target address failed: %w", err)
		}
		return &ServerSession{Conn: conn, Type: SessionTypeTCP, Target: target, UserHash: userHash}, nil
	default:
		return nil, fmt.Errorf("unknown kip message: %d", first.Type)
	}
}
