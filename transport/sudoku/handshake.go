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
	"sync"
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

// SuspiciousError indicates a potential probing attempt or protocol violation.
// When returned, Conn (if non-nil) should contain all bytes already consumed/buffered so the caller
// can perform a best-effort fallback relay (e.g. to a local web server) without losing the request.
type SuspiciousError struct {
	Err  error
	Conn net.Conn
}

func (e *SuspiciousError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *SuspiciousError) Unwrap() error { return e.Err }

type recordedConn struct {
	net.Conn
	recorded []byte
}

func (rc *recordedConn) GetBufferedAndRecorded() []byte { return rc.recorded }

type prefixedRecorderConn struct {
	net.Conn
	prefix []byte
}

func (pc *prefixedRecorderConn) GetBufferedAndRecorded() []byte {
	var rest []byte
	if r, ok := pc.Conn.(interface{ GetBufferedAndRecorded() []byte }); ok {
		rest = r.GetBufferedAndRecorded()
	}
	out := make([]byte, 0, len(pc.prefix)+len(rest))
	out = append(out, pc.prefix...)
	out = append(out, rest...)
	return out
}

// bufferedRecorderConn wraps a net.Conn and a shared bufio.Reader so we can expose buffered bytes.
// This is used for legacy HTTP mask parsing errors so callers can fall back to a real HTTP server.
type bufferedRecorderConn struct {
	net.Conn
	r        *bufio.Reader
	recorder *bytes.Buffer
	mu       sync.Mutex
}

func (bc *bufferedRecorderConn) Read(p []byte) (n int, err error) {
	n, err = bc.r.Read(p)
	if n > 0 && bc.recorder != nil {
		bc.mu.Lock()
		bc.recorder.Write(p[:n])
		bc.mu.Unlock()
	}
	return n, err
}

func (bc *bufferedRecorderConn) GetBufferedAndRecorded() []byte {
	if bc == nil {
		return nil
	}
	bc.mu.Lock()
	defer bc.mu.Unlock()

	var recorded []byte
	if bc.recorder != nil {
		recorded = bc.recorder.Bytes()
	}
	buffered := 0
	if bc.r != nil {
		buffered = bc.r.Buffered()
	}
	if buffered <= 0 {
		return recorded
	}
	peeked, _ := bc.r.Peek(buffered)
	full := make([]byte, len(recorded)+len(peeked))
	copy(full, recorded)
	copy(full[len(recorded):], peeked)
	return full
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

func (p *preBufferedConn) CloseWrite() error {
	if p == nil {
		return nil
	}
	if cw, ok := p.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (p *preBufferedConn) CloseRead() error {
	if p == nil {
		return nil
	}
	if cr, ok := p.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
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

func (c *directionalConn) CloseWrite() error {
	if c == nil {
		return nil
	}
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *directionalConn) CloseRead() error {
	if c == nil {
		return nil
	}
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
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

func maybeConsumeLegacyHTTPMask(rawConn net.Conn, r *bufio.Reader, cfg *ProtocolConfig) ([]byte, *SuspiciousError) {
	if rawConn == nil || r == nil || cfg == nil || cfg.DisableHTTPMask || !isLegacyHTTPMaskMode(cfg.HTTPMaskMode) {
		return nil, nil
	}

	peekBytes, _ := r.Peek(4) // ignore error; subsequent read will handle it
	if !httpmask.LooksLikeHTTPRequestStart(peekBytes) {
		return nil, nil
	}

	consumed, err := httpmask.ConsumeHeader(r)
	if err == nil {
		return consumed, nil
	}

	recorder := new(bytes.Buffer)
	if len(consumed) > 0 {
		recorder.Write(consumed)
	}
	badConn := &bufferedRecorderConn{Conn: rawConn, r: r, recorder: recorder}
	return consumed, &SuspiciousError{Err: fmt.Errorf("invalid http header: %w", err), Conn: badConn}
}

// ServerHandshake performs the server-side KIP handshake.
func ServerHandshake(rawConn net.Conn, cfg *ProtocolConfig) (net.Conn, *HandshakeMeta, error) {
	if rawConn == nil {
		return nil, nil, fmt.Errorf("nil conn")
	}
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

	bufReader := bufio.NewReader(rawConn)
	_ = rawConn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	defer func() { _ = rawConn.SetReadDeadline(time.Time{}) }()

	httpHeaderData, susp := maybeConsumeLegacyHTTPMask(rawConn, bufReader, cfg)
	if susp != nil {
		return nil, nil, susp
	}

	selectedTable, preRead, err := selectTableByProbe(bufReader, cfg, cfg.tableCandidates())
	if err != nil {
		combined := make([]byte, 0, len(httpHeaderData)+len(preRead))
		combined = append(combined, httpHeaderData...)
		combined = append(combined, preRead...)
		return nil, nil, &SuspiciousError{Err: err, Conn: &recordedConn{Conn: rawConn, recorded: combined}}
	}

	baseConn := &preBufferedConn{Conn: rawConn, buf: preRead}
	sConn, obfsConn := buildServerObfsConn(baseConn, cfg, selectedTable, true)

	seed := ServerAEADSeed(cfg.Key)
	pskC2S, pskS2C := derivePSKDirectionalBases(seed)
	// Server side: recv is client->server, send is server->client.
	rc, err := crypto.NewRecordConn(obfsConn, cfg.AEADMethod, pskS2C, pskC2S)
	if err != nil {
		return nil, nil, fmt.Errorf("setup crypto failed: %w", err)
	}

	msg, err := ReadKIPMessage(rc)
	if err != nil {
		return nil, nil, &SuspiciousError{Err: fmt.Errorf("handshake read failed: %w", err), Conn: &prefixedRecorderConn{Conn: sConn, prefix: httpHeaderData}}
	}
	if msg.Type != KIPTypeClientHello {
		return nil, nil, &SuspiciousError{Err: fmt.Errorf("unexpected handshake message: %d", msg.Type), Conn: &prefixedRecorderConn{Conn: sConn, prefix: httpHeaderData}}
	}
	ch, err := DecodeKIPClientHelloPayload(msg.Payload)
	if err != nil {
		return nil, nil, &SuspiciousError{Err: fmt.Errorf("decode client hello failed: %w", err), Conn: &prefixedRecorderConn{Conn: sConn, prefix: httpHeaderData}}
	}
	if absInt64(time.Now().Unix()-ch.Timestamp.Unix()) > int64(kipHandshakeSkew.Seconds()) {
		return nil, nil, &SuspiciousError{Err: fmt.Errorf("time skew/replay"), Conn: &prefixedRecorderConn{Conn: sConn, prefix: httpHeaderData}}
	}

	userHashHex := hex.EncodeToString(ch.UserHash[:])
	if !globalHandshakeReplay.allow(userHashHex, ch.Nonce, time.Now()) {
		return nil, nil, &SuspiciousError{Err: fmt.Errorf("replay"), Conn: &prefixedRecorderConn{Conn: sConn, prefix: httpHeaderData}}
	}

	curve := ecdh.X25519()
	serverEphemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, &SuspiciousError{Err: fmt.Errorf("ecdh generate failed: %w", err), Conn: &prefixedRecorderConn{Conn: sConn, prefix: httpHeaderData}}
	}
	shared, err := x25519SharedSecret(serverEphemeral, ch.ClientPub[:])
	if err != nil {
		return nil, nil, &SuspiciousError{Err: fmt.Errorf("ecdh failed: %w", err), Conn: &prefixedRecorderConn{Conn: sConn, prefix: httpHeaderData}}
	}
	sessC2S, sessS2C, err := deriveSessionDirectionalBases(seed, shared, ch.Nonce)
	if err != nil {
		return nil, nil, &SuspiciousError{Err: fmt.Errorf("derive session keys failed: %w", err), Conn: &prefixedRecorderConn{Conn: sConn, prefix: httpHeaderData}}
	}

	var serverPub [kipHelloPubSize]byte
	copy(serverPub[:], serverEphemeral.PublicKey().Bytes())
	sh := &KIPServerHello{
		Nonce:         ch.Nonce,
		ServerPub:     serverPub,
		SelectedFeats: ch.Features & KIPFeatAll,
	}
	if err := WriteKIPMessage(rc, KIPTypeServerHello, sh.EncodePayload()); err != nil {
		return nil, nil, &SuspiciousError{Err: fmt.Errorf("write server hello failed: %w", err), Conn: &prefixedRecorderConn{Conn: sConn, prefix: httpHeaderData}}
	}
	if err := rc.Rekey(sessS2C, sessC2S); err != nil {
		return nil, nil, &SuspiciousError{Err: fmt.Errorf("rekey failed: %w", err), Conn: &prefixedRecorderConn{Conn: sConn, prefix: httpHeaderData}}
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
