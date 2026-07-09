package outbound

import (
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/utils"
)

// parseHeaderCustomLayer builds a header-custom layer from raw settings per the
// XTLS FinalMask spec:
// https://xtls.github.io/ru/config/transports/finalmask.html#header-custom
//
// Note: randRange is the range of byte VALUES (default "0-255"), not the range
// of byte COUNT. The COUNT is given by rand. Per spec, servers/errors are
// server-side only and are not exposed here.
func parseHeaderCustomLayer(s FinalMaskLayerSettings) (finalMaskLayer, error) {
	cfg, err := parseHeaderCustomSettings(s)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("header-custom: no valid client entries")
	}
	return &headerCustomLayer{cfg: cfg}, nil
}

// HeaderCustomPacket mirrors one entry of a FinalMask header-custom client
// profile. Packet is polymorphic: []int for type=array, string for str/hex/base64.
type HeaderCustomPacket struct {
	Delay     int    `proxy:"delay,omitempty"`
	Rand      int    `proxy:"rand,omitempty"`
	RandRange string `proxy:"rand-range,omitempty"` // range of byte values, default "0-255"
	Type      string `proxy:"type,omitempty"`       // "", "array", "str", "hex", "base64"
	Packet    any    `proxy:"packet,omitempty"`     // []int (array) or string
}

type headerCustomSettings struct {
	groups []headerCustomGroup
}

type headerCustomGroup struct {
	packets []headerCustomEntry
}

type headerCustomEntry struct {
	delay    time.Duration
	data     []byte           // fixed payload (str/hex/base64/array)
	randSize int              // when > 0, generate randSize random bytes per injection
	valRange utils.Range[int] // range of byte values for random generation
}

func parseHeaderCustomSettings(s FinalMaskLayerSettings) (*headerCustomSettings, error) {
	if len(s.Clients) == 0 {
		return nil, nil
	}

	groups := make([]headerCustomGroup, 0, len(s.Clients))
	for gi, clientGroup := range s.Clients {
		entries := make([]headerCustomEntry, 0, len(clientGroup))
		for pi, p := range clientGroup {
			entry, err := p.parse()
			if err != nil {
				return nil, fmt.Errorf("header-custom: clients[%d][%d]: %w", gi, pi, err)
			}
			entries = append(entries, entry)
		}
		if len(entries) > 0 {
			groups = append(groups, headerCustomGroup{packets: entries})
		}
	}
	if len(groups) == 0 {
		return nil, nil
	}
	return &headerCustomSettings{groups: groups}, nil
}

func (p *HeaderCustomPacket) parse() (headerCustomEntry, error) {
	entry := headerCustomEntry{
		delay: time.Duration(p.Delay) * time.Millisecond,
	}

	// rand and packet are mutually exclusive per spec.
	if p.Rand > 0 && p.Packet != nil {
		return entry, fmt.Errorf("rand and packet are mutually exclusive")
	}

	if p.Rand > 0 {
		entry.randSize = p.Rand
		entry.valRange = parseValueRange(p.RandRange)
		return entry, nil
	}

	if p.Packet != nil {
		data, err := p.decodePacket()
		if err != nil {
			return entry, err
		}
		entry.data = data
		return entry, nil
	}

	return entry, fmt.Errorf("packet has neither rand nor packet")
}

// parseValueRange parses the byte-value range. Default is "0-255" (full byte
// range), equivalent to crypto/rand. Empty/invalid values fall back to default.
// End values >255 are clamped to 255.
func parseValueRange(s string) utils.Range[int] {
	if s == "" {
		return utils.NewRange(0, 255)
	}
	r, err := utils.NewSignedRange[int](s)
	if err != nil {
		return utils.NewRange(0, 255)
	}
	if r.End() > 255 {
		r = utils.NewRange(r.Start(), 255)
	}
	return r
}

func (p *HeaderCustomPacket) decodePacket() ([]byte, error) {
	switch p.Type {
	case "", "array":
		return decodeArrayPacket(p.Packet)
	case "str":
		s, ok := p.Packet.(string)
		if !ok {
			return nil, fmt.Errorf("type=str requires string packet, got %T", p.Packet)
		}
		return []byte(s), nil
	case "hex":
		s, ok := p.Packet.(string)
		if !ok {
			return nil, fmt.Errorf("type=hex requires string packet, got %T", p.Packet)
		}
		return hex.DecodeString(s)
	case "base64":
		s, ok := p.Packet.(string)
		if !ok {
			return nil, fmt.Errorf("type=base64 requires string packet, got %T", p.Packet)
		}
		return base64.StdEncoding.DecodeString(s)
	default:
		return nil, fmt.Errorf("unknown type %q", p.Type)
	}
}

// decodeArrayPacket converts the polymorphic Packet field into a byte slice
// when type=array. The proxy decoder stores YAML lists as []interface{}.
func decodeArrayPacket(v any) ([]byte, error) {
	switch val := v.(type) {
	case []interface{}:
		out := make([]byte, len(val))
		for i, e := range val {
			b, ok := toByte(e)
			if !ok {
				return nil, fmt.Errorf("array element %d is not a byte value: %T", i, e)
			}
			out[i] = b
		}
		return out, nil
	case []int:
		out := make([]byte, len(val))
		for i, e := range val {
			if e < 0 || e > 255 {
				return nil, fmt.Errorf("array element %d out of byte range: %d", i, e)
			}
			out[i] = byte(e)
		}
		return out, nil
	case string:
		// Accept string as a fallback for type=array if user wrote a string by mistake.
		return []byte(val), nil
	case nil:
		return nil, fmt.Errorf("array packet is empty")
	default:
		return nil, fmt.Errorf("array packet has unsupported type %T", v)
	}
}

func toByte(v any) (byte, bool) {
	switch x := v.(type) {
	case int:
		if x < 0 || x > 255 {
			return 0, false
		}
		return byte(x), true
	case int64:
		if x < 0 || x > 255 {
			return 0, false
		}
		return byte(x), true
	case float64:
		if x < 0 || x > 255 {
			return 0, false
		}
		return byte(x), true
	}
	return 0, false
}

func (e headerCustomEntry) bytes() ([]byte, error) {
	if len(e.data) > 0 {
		return e.data, nil
	}
	if e.randSize <= 0 {
		return nil, nil
	}
	buf := make([]byte, e.randSize)
	lo := e.valRange.Start()
	hi := e.valRange.End()
	if hi == 255 && lo == 0 {
		// Fast path: full range == crypto/rand.
		if _, err := cryptorand.Read(buf); err != nil {
			return nil, err
		}
		return buf, nil
	}
	// Constrained range: sample each byte uniformly in [lo, hi].
	span := hi - lo + 1
	if span <= 0 {
		span = 1
	}
	for i := range buf {
		buf[i] = byte(lo + rand.IntN(span))
	}
	return buf, nil
}

type headerCustomLayer struct {
	cfg *headerCustomSettings
}

func (l *headerCustomLayer) wrap(conn net.Conn) net.Conn {
	return newHeaderCustomConn(conn, l.cfg)
}

type headerCustomConn struct {
	net.Conn
	mu       sync.Mutex
	cfg      *headerCustomSettings
	injected bool
}

func newHeaderCustomConn(conn net.Conn, cfg *headerCustomSettings) *headerCustomConn {
	return &headerCustomConn{Conn: conn, cfg: cfg}
}

func (c *headerCustomConn) Write(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.injected {
		if err := c.injectPackets(); err != nil {
			return 0, err
		}
		c.injected = true
	}
	return c.Conn.Write(data)
}

func (c *headerCustomConn) injectPackets() error {
	// Pick one client profile at random per connection.
	group := c.cfg.groups[rand.IntN(len(c.cfg.groups))]
	for _, entry := range group.packets {
		if entry.delay > 0 {
			time.Sleep(entry.delay)
		}
		data, err := entry.bytes()
		if err != nil {
			return err
		}
		if len(data) == 0 {
			continue
		}
		if _, err := c.Conn.Write(data); err != nil {
			return err
		}
	}
	return nil
}

func (c *headerCustomConn) Read(b []byte) (int, error) {
	return c.Conn.Read(b)
}
