package sudoku

import (
	"bufio"
	"bytes"
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/metacubex/mihomo/transport/sudoku/crypto"
	"github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
)

func pickClientTable(cfg *ProtocolConfig) (*sudoku.Table, error) {
	candidates := cfg.tableCandidates()
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no table configured")
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	var b [1]byte
	if _, err := crand.Read(b[:]); err != nil {
		return nil, fmt.Errorf("random table pick failed: %w", err)
	}
	idx := int(b[0]) % len(candidates)
	return candidates[idx], nil
}

type readOnlyConn struct {
	*bytes.Reader
}

func (c *readOnlyConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (c *readOnlyConn) Close() error                     { return nil }
func (c *readOnlyConn) LocalAddr() net.Addr              { return nil }
func (c *readOnlyConn) RemoteAddr() net.Addr             { return nil }
func (c *readOnlyConn) SetDeadline(time.Time) error      { return nil }
func (c *readOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (c *readOnlyConn) SetWriteDeadline(time.Time) error { return nil }

func drainBuffered(r *bufio.Reader) ([]byte, error) {
	n := r.Buffered()
	if n <= 0 {
		return nil, nil
	}
	out := make([]byte, n)
	_, err := io.ReadFull(r, out)
	return out, err
}

func probeHandshakeBytes(probe []byte, cfg *ProtocolConfig, table *sudoku.Table) error {
	rc := &readOnlyConn{Reader: bytes.NewReader(probe)}
	_, obfsConn := buildServerObfsConn(rc, cfg, table, false)
	seed := ServerAEADSeed(cfg.Key)
	pskC2S, pskS2C := derivePSKDirectionalBases(seed)
	// Server side: recv is client->server, send is server->client.
	cConn, err := crypto.NewRecordConn(obfsConn, cfg.AEADMethod, pskS2C, pskC2S)
	if err != nil {
		return err
	}

	msg, err := ReadKIPMessage(cConn)
	if err != nil {
		return err
	}
	if msg.Type != KIPTypeClientHello {
		return fmt.Errorf("unexpected handshake message: %d", msg.Type)
	}
	ch, err := DecodeKIPClientHelloPayload(msg.Payload)
	if err != nil {
		return err
	}
	if absInt64(time.Now().Unix()-ch.Timestamp.Unix()) > int64(kipHandshakeSkew.Seconds()) {
		return fmt.Errorf("time skew/replay")
	}

	return nil
}

func selectTableByProbe(r *bufio.Reader, cfg *ProtocolConfig, tables []*sudoku.Table) (*sudoku.Table, []byte, error) {
	const (
		maxProbeBytes = 64 * 1024
		readChunk     = 4 * 1024
	)
	if len(tables) == 0 {
		return nil, nil, fmt.Errorf("no table candidates")
	}
	if len(tables) > 255 {
		return nil, nil, fmt.Errorf("too many table candidates: %d", len(tables))
	}

	// Copy so we can prune candidates without mutating the caller slice.
	candidates := make([]*sudoku.Table, 0, len(tables))
	for _, t := range tables {
		if t != nil {
			candidates = append(candidates, t)
		}
	}
	if len(candidates) == 0 {
		return nil, nil, fmt.Errorf("no table candidates")
	}

	probe, err := drainBuffered(r)
	if err != nil {
		return nil, nil, fmt.Errorf("drain buffered bytes failed: %w", err)
	}

	tmp := make([]byte, readChunk)
	for {
		if len(candidates) == 1 {
			tail, err := drainBuffered(r)
			if err != nil {
				return nil, nil, fmt.Errorf("drain buffered bytes failed: %w", err)
			}
			probe = append(probe, tail...)
			return candidates[0], probe, nil
		}

		needMore := false
		next := candidates[:0]
		for _, table := range candidates {
			err := probeHandshakeBytes(probe, cfg, table)
			if err == nil {
				tail, err := drainBuffered(r)
				if err != nil {
					return nil, nil, fmt.Errorf("drain buffered bytes failed: %w", err)
				}
				probe = append(probe, tail...)
				return table, probe, nil
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				needMore = true
				next = append(next, table)
			}
			// Definitive mismatch: drop table.
		}
		candidates = next

		if len(candidates) == 0 || !needMore {
			return nil, probe, fmt.Errorf("handshake table selection failed")
		}
		if len(probe) >= maxProbeBytes {
			return nil, probe, fmt.Errorf("handshake probe exceeded %d bytes", maxProbeBytes)
		}

		n, err := r.Read(tmp)
		if n > 0 {
			probe = append(probe, tmp[:n]...)
		}
		if err != nil {
			return nil, probe, fmt.Errorf("handshake probe read failed: %w", err)
		}
	}
}
