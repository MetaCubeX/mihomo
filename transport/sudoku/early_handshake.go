package sudoku

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/metacubex/mihomo/transport/sudoku/crypto"
	httpmaskobfs "github.com/metacubex/mihomo/transport/sudoku/obfs/httpmask"
	sudokuobfs "github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
)

const earlyKIPHandshakeTTL = 60 * time.Second

type EarlyCodecConfig struct {
	PSK                string
	AEAD               string
	EnablePureDownlink bool
	PaddingMin         int
	PaddingMax         int
}

type EarlyClientState struct {
	RequestPayload []byte

	cfg         EarlyCodecConfig
	table       *sudokuobfs.Table
	nonce       [kipHelloNonceSize]byte
	ephemeral   *ecdh.PrivateKey
	sessionC2S  []byte
	sessionS2C  []byte
	responseSet bool
}

type EarlyServerState struct {
	ResponsePayload []byte
	UserHash        string

	cfg        EarlyCodecConfig
	table      *sudokuobfs.Table
	sessionC2S []byte
	sessionS2C []byte
}

type ReplayAllowFunc func(userHash string, nonce [kipHelloNonceSize]byte, now time.Time) bool

type earlyMemoryConn struct {
	reader *bytes.Reader
	write  bytes.Buffer
}

func newEarlyMemoryConn(readBuf []byte) *earlyMemoryConn {
	return &earlyMemoryConn{reader: bytes.NewReader(readBuf)}
}

func (c *earlyMemoryConn) Read(p []byte) (int, error) {
	if c == nil || c.reader == nil {
		return 0, net.ErrClosed
	}
	return c.reader.Read(p)
}

func (c *earlyMemoryConn) Write(p []byte) (int, error) {
	if c == nil {
		return 0, net.ErrClosed
	}
	return c.write.Write(p)
}

func (c *earlyMemoryConn) Close() error                     { return nil }
func (c *earlyMemoryConn) LocalAddr() net.Addr              { return earlyDummyAddr("local") }
func (c *earlyMemoryConn) RemoteAddr() net.Addr             { return earlyDummyAddr("remote") }
func (c *earlyMemoryConn) SetDeadline(time.Time) error      { return nil }
func (c *earlyMemoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *earlyMemoryConn) SetWriteDeadline(time.Time) error { return nil }
func (c *earlyMemoryConn) Written() []byte                  { return append([]byte(nil), c.write.Bytes()...) }

type earlyDummyAddr string

func (a earlyDummyAddr) Network() string { return string(a) }
func (a earlyDummyAddr) String() string  { return string(a) }

func buildEarlyClientObfsConn(raw net.Conn, cfg EarlyCodecConfig, table *sudokuobfs.Table) net.Conn {
	base := sudokuobfs.NewConn(raw, table, cfg.PaddingMin, cfg.PaddingMax, false)
	if cfg.EnablePureDownlink {
		return base
	}
	packed := sudokuobfs.NewPackedConn(raw, table, cfg.PaddingMin, cfg.PaddingMax)
	return newDirectionalConn(raw, packed, base)
}

func buildEarlyServerObfsConn(raw net.Conn, cfg EarlyCodecConfig, table *sudokuobfs.Table) net.Conn {
	uplink := sudokuobfs.NewConn(raw, table, cfg.PaddingMin, cfg.PaddingMax, false)
	if cfg.EnablePureDownlink {
		return uplink
	}
	packed := sudokuobfs.NewPackedConn(raw, table, cfg.PaddingMin, cfg.PaddingMax)
	return newDirectionalConn(raw, uplink, packed, packed.Flush)
}

func NewEarlyClientState(cfg EarlyCodecConfig, table *sudokuobfs.Table, userHash [kipHelloUserHashSize]byte, feats uint32) (*EarlyClientState, error) {
	if table == nil {
		return nil, fmt.Errorf("nil table")
	}

	curve := ecdh.X25519()
	ephemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdh generate failed: %w", err)
	}

	var nonce [kipHelloNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("nonce generate failed: %w", err)
	}

	var clientPub [kipHelloPubSize]byte
	copy(clientPub[:], ephemeral.PublicKey().Bytes())
	hello := &KIPClientHello{
		Timestamp: time.Now(),
		UserHash:  userHash,
		Nonce:     nonce,
		ClientPub: clientPub,
		Features:  feats,
	}

	mem := newEarlyMemoryConn(nil)
	obfsConn := buildEarlyClientObfsConn(mem, cfg, table)
	pskC2S, pskS2C := derivePSKDirectionalBases(cfg.PSK)
	rc, err := crypto.NewRecordConn(obfsConn, cfg.AEAD, pskC2S, pskS2C)
	if err != nil {
		return nil, fmt.Errorf("client early crypto setup failed: %w", err)
	}
	if err := WriteKIPMessage(rc, KIPTypeClientHello, hello.EncodePayload()); err != nil {
		return nil, fmt.Errorf("write early client hello failed: %w", err)
	}

	return &EarlyClientState{
		RequestPayload: mem.Written(),
		cfg:            cfg,
		table:          table,
		nonce:          nonce,
		ephemeral:      ephemeral,
	}, nil
}

func (s *EarlyClientState) ProcessResponse(payload []byte) error {
	if s == nil {
		return fmt.Errorf("nil client state")
	}

	mem := newEarlyMemoryConn(payload)
	obfsConn := buildEarlyClientObfsConn(mem, s.cfg, s.table)
	pskC2S, pskS2C := derivePSKDirectionalBases(s.cfg.PSK)
	rc, err := crypto.NewRecordConn(obfsConn, s.cfg.AEAD, pskC2S, pskS2C)
	if err != nil {
		return fmt.Errorf("client early crypto setup failed: %w", err)
	}

	msg, err := ReadKIPMessage(rc)
	if err != nil {
		return fmt.Errorf("read early server hello failed: %w", err)
	}
	if msg.Type != KIPTypeServerHello {
		return fmt.Errorf("unexpected early handshake message: %d", msg.Type)
	}
	sh, err := DecodeKIPServerHelloPayload(msg.Payload)
	if err != nil {
		return fmt.Errorf("decode early server hello failed: %w", err)
	}
	if sh.Nonce != s.nonce {
		return fmt.Errorf("early handshake nonce mismatch")
	}

	shared, err := x25519SharedSecret(s.ephemeral, sh.ServerPub[:])
	if err != nil {
		return fmt.Errorf("ecdh failed: %w", err)
	}
	s.sessionC2S, s.sessionS2C, err = deriveSessionDirectionalBases(s.cfg.PSK, shared, s.nonce)
	if err != nil {
		return fmt.Errorf("derive session keys failed: %w", err)
	}
	s.responseSet = true
	return nil
}

func (s *EarlyClientState) WrapConn(raw net.Conn) (net.Conn, error) {
	if s == nil {
		return nil, fmt.Errorf("nil client state")
	}
	if !s.responseSet {
		return nil, fmt.Errorf("early handshake not completed")
	}

	obfsConn := buildEarlyClientObfsConn(raw, s.cfg, s.table)
	rc, err := crypto.NewRecordConn(obfsConn, s.cfg.AEAD, s.sessionC2S, s.sessionS2C)
	if err != nil {
		return nil, fmt.Errorf("setup client session crypto failed: %w", err)
	}
	return rc, nil
}

func (s *EarlyClientState) Ready() bool {
	return s != nil && s.responseSet
}

func NewHTTPMaskClientEarlyHandshake(cfg EarlyCodecConfig, table *sudokuobfs.Table, userHash [kipHelloUserHashSize]byte, feats uint32) (*httpmaskobfs.ClientEarlyHandshake, error) {
	state, err := NewEarlyClientState(cfg, table, userHash, feats)
	if err != nil {
		return nil, err
	}
	return &httpmaskobfs.ClientEarlyHandshake{
		RequestPayload: state.RequestPayload,
		HandleResponse: state.ProcessResponse,
		Ready:          state.Ready,
		WrapConn:       state.WrapConn,
	}, nil
}

func ProcessEarlyClientPayload(cfg EarlyCodecConfig, tables []*sudokuobfs.Table, payload []byte, allowReplay ReplayAllowFunc) (*EarlyServerState, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("empty early payload")
	}
	if len(tables) == 0 {
		return nil, fmt.Errorf("no tables configured")
	}

	var firstErr error
	for _, table := range tables {
		state, err := processEarlyClientPayloadForTable(cfg, table, payload, allowReplay)
		if err == nil {
			return state, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("early handshake probe failed")
	}
	return nil, firstErr
}

func processEarlyClientPayloadForTable(cfg EarlyCodecConfig, table *sudokuobfs.Table, payload []byte, allowReplay ReplayAllowFunc) (*EarlyServerState, error) {
	mem := newEarlyMemoryConn(payload)
	obfsConn := buildEarlyServerObfsConn(mem, cfg, table)
	pskC2S, pskS2C := derivePSKDirectionalBases(cfg.PSK)
	rc, err := crypto.NewRecordConn(obfsConn, cfg.AEAD, pskS2C, pskC2S)
	if err != nil {
		return nil, err
	}

	msg, err := ReadKIPMessage(rc)
	if err != nil {
		return nil, err
	}
	if msg.Type != KIPTypeClientHello {
		return nil, fmt.Errorf("unexpected handshake message: %d", msg.Type)
	}
	ch, err := DecodeKIPClientHelloPayload(msg.Payload)
	if err != nil {
		return nil, err
	}
	if absInt64(time.Now().Unix()-ch.Timestamp.Unix()) > int64(earlyKIPHandshakeTTL.Seconds()) {
		return nil, fmt.Errorf("time skew/replay")
	}

	userHash := hex.EncodeToString(ch.UserHash[:])
	if allowReplay != nil && !allowReplay(userHash, ch.Nonce, time.Now()) {
		return nil, fmt.Errorf("replay detected")
	}

	curve := ecdh.X25519()
	serverEphemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdh generate failed: %w", err)
	}
	shared, err := x25519SharedSecret(serverEphemeral, ch.ClientPub[:])
	if err != nil {
		return nil, fmt.Errorf("ecdh failed: %w", err)
	}
	sessionC2S, sessionS2C, err := deriveSessionDirectionalBases(cfg.PSK, shared, ch.Nonce)
	if err != nil {
		return nil, fmt.Errorf("derive session keys failed: %w", err)
	}

	var serverPub [kipHelloPubSize]byte
	copy(serverPub[:], serverEphemeral.PublicKey().Bytes())
	serverHello := &KIPServerHello{
		Nonce:         ch.Nonce,
		ServerPub:     serverPub,
		SelectedFeats: ch.Features & KIPFeatAll,
	}

	respMem := newEarlyMemoryConn(nil)
	respObfs := buildEarlyServerObfsConn(respMem, cfg, table)
	respConn, err := crypto.NewRecordConn(respObfs, cfg.AEAD, pskS2C, pskC2S)
	if err != nil {
		return nil, fmt.Errorf("server early crypto setup failed: %w", err)
	}
	if err := WriteKIPMessage(respConn, KIPTypeServerHello, serverHello.EncodePayload()); err != nil {
		return nil, fmt.Errorf("write early server hello failed: %w", err)
	}

	return &EarlyServerState{
		ResponsePayload: respMem.Written(),
		UserHash:        userHash,
		cfg:             cfg,
		table:           table,
		sessionC2S:      sessionC2S,
		sessionS2C:      sessionS2C,
	}, nil
}

func (s *EarlyServerState) WrapConn(raw net.Conn) (net.Conn, error) {
	if s == nil {
		return nil, fmt.Errorf("nil server state")
	}
	obfsConn := buildEarlyServerObfsConn(raw, s.cfg, s.table)
	rc, err := crypto.NewRecordConn(obfsConn, s.cfg.AEAD, s.sessionS2C, s.sessionC2S)
	if err != nil {
		return nil, fmt.Errorf("setup server session crypto failed: %w", err)
	}
	return rc, nil
}

func NewHTTPMaskServerEarlyHandshake(cfg EarlyCodecConfig, tables []*sudokuobfs.Table, allowReplay ReplayAllowFunc) *httpmaskobfs.TunnelServerEarlyHandshake {
	return &httpmaskobfs.TunnelServerEarlyHandshake{
		Prepare: func(payload []byte) (*httpmaskobfs.PreparedServerEarlyHandshake, error) {
			state, err := ProcessEarlyClientPayload(cfg, tables, payload, allowReplay)
			if err != nil {
				return nil, err
			}
			return &httpmaskobfs.PreparedServerEarlyHandshake{
				ResponsePayload: state.ResponsePayload,
				WrapConn:        state.WrapConn,
				UserHash:        state.UserHash,
			}, nil
		},
	}
}
