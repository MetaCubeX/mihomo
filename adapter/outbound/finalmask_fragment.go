package outbound

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/utils"
)

// parseFragmentLayer builds a fragment layer from raw settings per the XTLS
// FinalMask spec: https://xtls.github.io/ru/config/transports/finalmask.html#fragment
func parseFragmentLayer(s FinalMaskLayerSettings) (finalMaskLayer, error) {
	cfg, err := parseFragmentSettings(s)
	if err != nil {
		return nil, err
	}
	return &fragmentLayer{cfg: cfg}, nil
}

type fragmentSettings struct {
	packets    string // "tlshello" or "" / range string like "1-3"
	lengths    []utils.Range[int]
	delays     []utils.Range[int]
	maxSplit   int              // 0 = unlimited
	writeRange utils.Range[int] // used when packets is a range
	tlshello   bool
}

func parseFragmentSettings(s FinalMaskLayerSettings) (*fragmentSettings, error) {
	packets := s.Packets
	if packets == "" {
		packets = "tlshello"
	}

	cfg := &fragmentSettings{packets: packets}

	if packets == "tlshello" {
		cfg.tlshello = true
	} else {
		r, err := utils.NewSignedRange[int](packets)
		if err != nil {
			return nil, fmt.Errorf("fragment: invalid packets %q: %w", packets, err)
		}
		if r.Start() < 1 {
			return nil, fmt.Errorf("fragment: packets range %q must start at 1", packets)
		}
		cfg.writeRange = r
	}

	for _, l := range s.Lengths {
		r, err := utils.NewSignedRange[int](l)
		if err != nil {
			return nil, fmt.Errorf("fragment: invalid length %q: %w", l, err)
		}
		cfg.lengths = append(cfg.lengths, r)
	}
	// Spec: all entries except the last may be 0. The last must be non-zero
	// (otherwise we'd loop forever on idle passes).
	if n := len(cfg.lengths); n > 0 {
		last := cfg.lengths[n-1]
		if last.Start() == 0 && last.End() == 0 {
			return nil, fmt.Errorf("fragment: last length entry must be non-zero")
		}
	}

	for _, d := range s.Delays {
		r, err := utils.NewSignedRange[int](d)
		if err != nil {
			return nil, fmt.Errorf("fragment: invalid delay %q: %w", d, err)
		}
		cfg.delays = append(cfg.delays, r)
	}

	if s.MaxSplit != "" {
		r, err := utils.NewSignedRange[int](s.MaxSplit)
		if err != nil {
			return nil, fmt.Errorf("fragment: invalid max-split %q: %w", s.MaxSplit, err)
		}
		cfg.maxSplit = r.End()
	}

	return cfg, nil
}

type fragmentLayer struct {
	cfg *fragmentSettings
}

func (l *fragmentLayer) wrap(conn net.Conn) net.Conn {
	return newFragmentConn(conn, l.cfg)
}

type fragmentPhase int

const (
	phaseFragmenting fragmentPhase = iota
	phasePassthrough
)

type fragmentConn struct {
	net.Conn
	mu              sync.Mutex
	cfg             *fragmentSettings
	phase           fragmentPhase
	writeCount      int // 1-indexed; only used in "1-3" mode
	bytesFragmented int // only used in tlshello mode
	totalToFragment int // only used in tlshello mode
}

func newFragmentConn(conn net.Conn, cfg *fragmentSettings) *fragmentConn {
	return &fragmentConn{
		Conn:  conn,
		cfg:   cfg,
		phase: phaseFragmenting,
	}
}

func (c *fragmentConn) Write(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.phase == phasePassthrough {
		return c.Conn.Write(data)
	}

	if c.cfg.tlshello {
		return c.writeTLSHello(data)
	}
	return c.writeIndexed(data)
}

func (c *fragmentConn) writeTLSHello(data []byte) (int, error) {
	if c.bytesFragmented == 0 {
		// First write: must look like a TLS handshake record.
		if len(data) < 5 || data[0] != 0x16 {
			c.phase = phasePassthrough
			return c.Conn.Write(data)
		}
		recordLen := int(binary.BigEndian.Uint16(data[3:5]))
		c.totalToFragment = recordLen + 5
	}
	n, err := c.fragmentWrite(data)
	if err != nil {
		return n, err
	}
	if c.bytesFragmented >= c.totalToFragment {
		c.phase = phasePassthrough
	}
	return n, nil
}

func (c *fragmentConn) writeIndexed(data []byte) (int, error) {
	c.writeCount++
	r := c.cfg.writeRange
	if c.writeCount < r.Start() {
		return c.Conn.Write(data)
	}
	if c.writeCount > r.End() {
		c.phase = phasePassthrough
		return c.Conn.Write(data)
	}
	n, err := c.fragmentWrite(data)
	if err != nil {
		return n, err
	}
	if c.writeCount >= r.End() {
		c.phase = phasePassthrough
	}
	return n, nil
}

// fragmentWrite splits data according to the lengths/delays arrays.
// maxSplit caps the number of actual fragments produced; idle passes do not
// count toward that limit (per spec — maxSplit limits parts, not passes).
func (c *fragmentConn) fragmentWrite(data []byte) (int, error) {
	offset := 0
	passIdx := 0
	fragCount := 0
	for offset < len(data) {
		if c.cfg.maxSplit > 0 && fragCount >= c.cfg.maxSplit {
			// Limit reached: write the rest as a single chunk, no further delay.
			if _, err := c.Conn.Write(data[offset:]); err != nil {
				return offset, err
			}
			return len(data), nil
		}

		lengthRange := c.pickLength(passIdx)
		fragSize := randomInRange(lengthRange)
		isLast := passIdx >= len(c.cfg.lengths)-1

		// Idle pass: length is zero on a non-last entry. Wait the corresponding
		// delay, then advance without producing a fragment.
		if fragSize == 0 && !isLast {
			if delay := randomInRange(c.pickDelay(passIdx)); delay > 0 {
				time.Sleep(time.Duration(delay) * time.Millisecond)
			}
			passIdx++
			continue
		}

		remaining := len(data) - offset
		// Last length entry equal to 0 (degenerate config) means: send the rest.
		if fragSize <= 0 {
			fragSize = remaining
		}
		if fragSize > remaining {
			fragSize = remaining
		}

		if _, err := c.Conn.Write(data[offset : offset+fragSize]); err != nil {
			return offset, err
		}
		offset += fragSize
		c.bytesFragmented += fragSize
		passIdx++
		fragCount++

		// tlshello: stop once we've covered the whole ClientHello.
		if c.cfg.tlshello && c.bytesFragmented >= c.totalToFragment {
			break
		}

		// Delay after this fragment (delays are pass-indexed).
		//
		// TODO(spec-compliance): per FinalMask spec, when delay==0 AND mode is
		// tlshello, the fragmented ClientHello must be sent as a SINGLE TCP
		// segment (if it fits in MSS/MTU) — i.e. write+flush with TCP_NODELAY
		// or cork the socket so the kernel doesn't split our Write()s into
		// separate packets. Today delay==0 just means "no Sleep", and the
		// kernel is free to fragment the stream on its own, which defeats the
		// purpose for users who set delays=["0"] intentionally.
		// Implementing this requires per-conn socket option juggling
		// (TCP_NODELAY/TCP_CORK or equivalent) and a flush after the last
		// fragment — non-trivial across network types. See:
		// https://xtls.github.io/ru/config/transports/finalmask.html#fragment
		if delay := randomInRange(c.pickDelay(passIdx - 1)); delay > 0 {
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}
	return len(data), nil
}

func (c *fragmentConn) pickLength(passIdx int) utils.Range[int] {
	if len(c.cfg.lengths) == 0 {
		return utils.NewRange(0, 0)
	}
	if passIdx >= len(c.cfg.lengths) {
		return c.cfg.lengths[len(c.cfg.lengths)-1]
	}
	return c.cfg.lengths[passIdx]
}

func (c *fragmentConn) pickDelay(passIdx int) utils.Range[int] {
	if len(c.cfg.delays) == 0 {
		return utils.NewRange(0, 0)
	}
	if passIdx >= len(c.cfg.delays) {
		return c.cfg.delays[len(c.cfg.delays)-1]
	}
	return c.cfg.delays[passIdx]
}

func (c *fragmentConn) Read(b []byte) (int, error) {
	return c.Conn.Read(b)
}
