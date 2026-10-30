package miu

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/padding"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
)

const (
	// How long an idle lane stays in the pool. The warmLanes most recently returned ones are kept for
	// warmLaneIdle (two clicks are often more than half a minute apart, and an empty pool means another
	// handshake; idle lanes send no heartbeats, so keeping a few costs next to nothing), the others are
	// closed after defaultLaneIdle. Neither exceeds what the server announced minus 5s.
	defaultLaneIdle = 30 * time.Second
	warmLaneIdle    = 120 * time.Second
	warmLanes       = 4
	// abortDrain is how long an aborted stream waits for the server's END before giving the lane up.
	abortDrain = 3 * time.Second
	// Only when two streams are opened within laneBurstWindow is the pool topped up to minIdle lanes in
	// the background: an occasional background connection is not worth extra handshakes.
	laneBurstWindow = 10 * time.Second
	defaultMinIdle  = 2
	maxIdleLanes    = 32
	// firstPayloadWait is how long a new stream waits for the application's first bytes, so that they
	// leave in the same packet as OPEN.
	firstPayloadWait = 10 * time.Millisecond
	// replayLimit: a stream that hit a dead pooled lane is replayed on a fresh one only while it has
	// sent no more than this much and has not received anything.
	replayLimit = 64 << 10
)

// ErrClientClosed is returned by a Client that has been closed.
var ErrClientClosed = errors.New("miu: client closed")

// ClientConfig configures a Client. PSK and Dial are required.
type ClientConfig struct {
	// PSK is the pre-shared key, used as a string exactly as the server has it.
	PSK string
	// PaddingScheme overrides the PSK-derived initial scheme when non-empty.
	PaddingScheme string
	// Dial opens a connection to the server and completes the outer TLS handshake on it. Raw segments
	// are available when the result is a Go TLS connection (see tlsBuffers) sitting directly on the
	// TCP connection.
	Dial func(ctx context.Context) (net.Conn, error)
	// LaneIdle is how long an idle lane beyond the newest four is kept (default 30s).
	LaneIdle time.Duration
	// MinIdle is how many idle lanes are kept warm while streams are being opened in a row (default 2).
	MinIdle int
	// DisableRaw turns raw segments off: the client declares raw=0 and never sends any.
	DisableRaw bool
}

// Client opens streams to one server over a pool of lanes.
type Client struct {
	cfg   ClientConfig
	token [32]byte

	paddingMu sync.RWMutex
	padding   *padding.PaddingFactory

	mu       sync.Mutex
	idle     []idleLane
	pending  int
	lastOpen time.Time
	closed   bool
}

type idleLane struct {
	l     *lane
	since time.Time
	// used: the lane has carried a stream, so ServerSettings has been consumed and nothing should
	// arrive on it while it is idle.
	used bool
}

func NewClient(cfg ClientConfig) (*Client, error) {
	token, err := pskToken(cfg.PSK)
	if err != nil {
		return nil, err
	}
	if cfg.Dial == nil {
		return nil, errors.New("miu: no dialer")
	}
	if cfg.LaneIdle <= 0 {
		cfg.LaneIdle = defaultLaneIdle
	}
	if cfg.MinIdle <= 0 {
		cfg.MinIdle = defaultMinIdle
	}
	scheme := cfg.PaddingScheme
	if scheme == "" {
		derived, err := derivedScheme(token)
		if err != nil {
			return nil, err
		}
		scheme = derived
	}
	p := padding.NewPaddingFactory([]byte(scheme))
	if p == nil {
		return nil, errors.New("miu: bad padding scheme")
	}
	return &Client{cfg: cfg, token: token, padding: p}, nil
}

// ---- the lane pool ----

func (c *Client) currentPadding() *padding.PaddingFactory {
	c.paddingMu.RLock()
	p := c.padding
	c.paddingMu.RUnlock()
	if p == nil {
		return padding.NewPaddingFactory(padding.DefaultPaddingScheme)
	}
	return p
}

func (c *Client) updatePadding(p *padding.PaddingFactory) {
	if p == nil {
		return
	}
	c.paddingMu.Lock()
	c.padding = p
	c.paddingMu.Unlock()
}

// dial opens a new lane: the outer handshake, then the authentication header, its padding and Settings
// in a single write. Nothing is waited for.
func (c *Client) dial(ctx context.Context) (*lane, error) {
	conn, err := c.cfg.Dial(ctx)
	if err != nil {
		return nil, err
	}
	l := newLane(conn, false, !c.cfg.DisableRaw)
	l.client = c
	l.scheme.Store(c.currentPadding())
	scheme := l.scheme.Load()
	padlen := authPadding(scheme)
	hello := append(make([]byte, 0, authHead+padlen+64), c.token[:]...)
	hello = append(hello, byte(padlen>>8), byte(padlen))
	hello = append(hello, make([]byte, padlen)...)
	hello = appendFrame(hello, frSettings, l.settingsText("\npadding-md5="+scheme.Md5))
	if err := l.write(hello); err != nil {
		l.close()
		return nil, err
	}
	l.event("dial")
	return l, nil
}

// authPadding is the length of the padding that follows the authentication token: item 0 of the scheme.
func authPadding(scheme *padding.PaddingFactory) int {
	if sizes := scheme.GenerateRecordPayloadSizes(0); len(sizes) > 0 && sizes[0] > 0 && sizes[0] <= 0xffff {
		return sizes[0]
	}
	return 0
}

// ttl is how long the lane ranked rank from the newest (0 = newest) may stay in the pool.
func (c *Client) ttl(l *lane, rank int) time.Duration {
	d := c.cfg.LaneIdle
	if rank < warmLanes && d < warmLaneIdle {
		d = warmLaneIdle
	}
	if peer := time.Duration(l.peerIdle.Load()) * time.Second; peer > 10*time.Second && peer-5*time.Second < d {
		d = peer - 5*time.Second
	}
	return d
}

// takeIdle returns the most recently returned idle lane that is still alive.
func (c *Client) takeIdle(now time.Time) (*lane, bool) {
	for {
		c.mu.Lock()
		n := len(c.idle)
		if n == 0 {
			c.mu.Unlock()
			return nil, false
		}
		it := c.idle[n-1]
		c.idle = c.idle[:n-1]
		c.mu.Unlock()

		alive, pending := connAlive(it.l.sock)
		// Nothing should arrive on an idle lane that has carried a stream: if something has, the server
		// is closing it (close_notify).
		if now.Sub(it.since) < c.ttl(it.l, 0) && alive && !(pending && it.used) {
			return it.l, it.used
		}
		it.l.close()
	}
}

// get returns a lane: one from the pool if there is any, a freshly dialed one otherwise. When streams
// are being opened in a row it also warms the pool up in the background.
func (c *Client) get(ctx context.Context) (l *lane, pooled, used bool, err error) {
	now := time.Now()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, false, false, ErrClientClosed
	}
	c.mu.Unlock()
	l, used = c.takeIdle(now)

	c.mu.Lock()
	burst := !c.lastOpen.IsZero() && now.Sub(c.lastOpen) <= laneBurstWindow
	c.lastOpen = now
	warm := 0
	if burst {
		if warm = c.cfg.MinIdle - len(c.idle) - c.pending; warm < 0 {
			warm = 0
		}
		c.pending += warm
	}
	c.mu.Unlock()
	for i := 0; i < warm; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), defaultDialTimeout)
			nl, err := c.dial(ctx)
			cancel()
			if err == nil {
				c.put(nl, false)
			}
			c.mu.Lock()
			c.pending--
			c.mu.Unlock()
		}()
	}

	if l != nil {
		l.event("reuse")
		return l, true, used, nil
	}
	l, err = c.dial(ctx)
	return l, false, false, err
}

// put returns a lane to the pool.
func (c *Client) put(l *lane, used bool) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		l.close()
		return
	}
	if len(c.idle) >= maxIdleLanes {
		c.idle[0].l.close()
		c.idle = c.idle[1:]
	}
	c.idle = append(c.idle, idleLane{l: l, since: time.Now(), used: used})
	c.mu.Unlock()
	time.AfterFunc(c.cfg.LaneIdle+time.Second, c.sweep)
	time.AfterFunc(warmLaneIdle+time.Second, c.sweep)
}

// sweep closes the idle lanes that have been in the pool for too long.
func (c *Client) sweep() {
	now := time.Now()
	c.mu.Lock()
	keep := c.idle[:0]
	var stale []*lane
	for i, it := range c.idle {
		if now.Sub(it.since) < c.ttl(it.l, len(c.idle)-1-i) {
			keep = append(keep, it)
		} else {
			stale = append(stale, it.l)
		}
	}
	c.idle = keep
	c.mu.Unlock()
	for _, l := range stale {
		l.close()
	}
}

// closeIdle closes every idle lane. Streams in progress are not touched.
func (c *Client) closeIdle() {
	c.mu.Lock()
	idle := c.idle
	c.idle = nil
	c.mu.Unlock()
	for _, it := range idle {
		it.l.close()
	}
}

// Close closes the idle lanes and makes the client refuse new streams. A stream in progress keeps
// working; its lane is closed when the stream ends.
func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.closeIdle()
	return nil
}

// DialContext opens a stream to destination (a domain name is resolved by the server). A destination
// of uot.RequestDestination carries UDP over the stream.
//
// The call returns as soon as a lane is at hand: the server does not acknowledge the destination, so a
// target that cannot be reached shows up as an immediate end of stream on the first Read. The returned
// connection also has a CloseWrite method. Closing it before both directions have ended aborts the
// stream (the lane still goes back to the pool).
func (c *Client) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	var addr bytes.Buffer
	if err := M.SocksaddrSerializer.WriteAddrPort(&addr, destination); err != nil {
		return nil, err
	}
	return c.open(ctx, appendFrame(nil, frOpen, addr.Bytes()), destination)
}

// isUoT reports whether a stream to destination carries UDP packets rather than a byte stream.
func isUoT(destination M.Socksaddr) bool {
	return destination.Fqdn == uot.MagicAddress || destination.Fqdn == uot.LegacyMagicAddress
}
