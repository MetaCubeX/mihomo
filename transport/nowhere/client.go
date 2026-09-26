package nowhere

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

type ClientConfig struct {
	Password               string
	Up, Down               string
	Mux, Morph, MorphFull8 bool
	TLSConfig              *tls.Config
	DialTCP                func(context.Context) (net.Conn, error)
	DialUDP                func(context.Context) (net.PacketConn, net.Addr, error)
}
type Client struct {
	config         ClientConfig
	key            [32]byte
	session        [16]byte
	morph          *morphKeys
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	nextID         uint32
	flows          map[uint32]*flowConn
	qmu            sync.Mutex
	quic           *quicSession
	quicConnecting chan struct{}
	mmu            sync.Mutex
	mux            []*muxConn
	muxConnecting  int
	muxChanged     chan struct{}
	route          atomic.Uint64
}

func NewClient(config ClientConfig) (*Client, error) {
	key, err := authKey(config.Password)
	if err != nil {
		return nil, err
	}
	if config.Up == "" {
		config.Up = "tcp"
	}
	if config.Down == "" {
		config.Down = "tcp"
	}
	for _, v := range []string{config.Up, config.Down} {
		if v != "tcp" && v != "udp" && v != "mix" {
			return nil, errors.New("nowhere: up/down must be tcp, udp or mix")
		}
	}
	if config.TLSConfig == nil || config.DialTCP == nil || config.DialUDP == nil {
		return nil, errors.New("nowhere: missing TLS configuration or dialer")
	}
	config.TLSConfig = config.TLSConfig.Clone()
	config.TLSConfig.MinVersion = tls.VersionTLS13
	config.TLSConfig.NextProtos = []string{ALPN}
	c := &Client{config: config, key: key, flows: make(map[uint32]*flowConn)}
	if _, err = rand.Read(c.session[:]); err != nil {
		return nil, err
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	if config.Morph {
		c.morph = newMorphKeys(config.Password)
	}
	return c, nil
}
func quicConfig() *quic.Config {
	return &quic.Config{EnableDatagrams: true, MaxIncomingStreams: 4096, MaxIncomingUniStreams: -1, HandshakeIdleTimeout: 10 * time.Second, MaxIdleTimeout: 60 * time.Second, KeepAlivePeriod: 20 * time.Second, InitialStreamReceiveWindow: streamWindow, MaxStreamReceiveWindow: streamWindow, InitialConnectionReceiveWindow: connWindow, MaxConnectionReceiveWindow: connWindow, MaxDatagramFrameSize: 65535}
}
func (c *Client) Close() error {
	c.cancel()
	c.mu.Lock()
	flows := make([]*flowConn, 0, len(c.flows))
	for _, f := range c.flows {
		if f != nil {
			flows = append(flows, f)
		}
	}
	c.flows = make(map[uint32]*flowConn)
	c.mu.Unlock()
	for _, f := range flows {
		f.Close()
	}
	c.qmu.Lock()
	q := c.quic
	c.quic = nil
	c.qmu.Unlock()
	c.mmu.Lock()
	muxes := c.mux
	c.mux = nil
	c.signalMux()
	c.mmu.Unlock()
	if q != nil {
		q.Close()
	}
	for _, m := range muxes {
		m.Close()
	}
	return nil
}

// watch closes a setup lane on cancellation and waits for the watcher before
// transferring ownership. A successful Dial never inherits its setup context.
func watch(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	return func() { close(done); <-exited }
}
func (c *Client) dialTLS(ctx context.Context) (net.Conn, error) {
	raw, err := c.config.DialTCP(ctx)
	if err != nil {
		return nil, err
	}
	stop := watch(ctx, raw)
	defer stop()
	success := false
	defer func() {
		if !success {
			raw.Close()
		}
	}()
	dl := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	_ = raw.SetDeadline(dl)
	conn := raw
	if c.morph != nil {
		conn, err = wrapMorphTCP(raw, c.morph, true, c.config.MorphFull8)
		if err != nil {
			return nil, err
		}
	}
	t := tls.Client(conn, c.config.TLSConfig)
	if err = t.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	exp, err := exporter(t.ConnectionState())
	if err != nil {
		return nil, err
	}
	frame := authFrame(c.key, carrierTLS, exp, c.session)
	if err = writeFull(t, frame[:]); err != nil {
		return nil, err
	}
	_ = t.SetDeadline(time.Time{})
	success = true
	return t, nil
}
func (c *Client) dialQUIC(ctx context.Context) (*quicSession, error) {
	pc, addr, err := c.config.DialUDP(ctx)
	if err != nil {
		return nil, err
	}
	if c.morph != nil {
		pc = wrapMorphUDP(pc, c.morph, true)
	}
	cfg := quicConfig()
	if c.morph != nil {
		cfg.DisablePathMTUDiscovery = true
	}
	conn, err := quic.Dial(ctx, pc, addr, c.config.TLSConfig, cfg)
	if err != nil {
		pc.Close()
		return nil, err
	}
	q := newQUICSession(conn, pc)
	success := false
	defer func() {
		if !success {
			q.Close()
		}
	}()
	exp, err := exporter(conn.ConnectionState().TLS)
	if err != nil {
		return nil, err
	}
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	l := &quicStream{Stream: s, conn: conn}
	stop := watch(ctx, l)
	defer stop()
	_ = s.SetWriteDeadline(time.Now().Add(10 * time.Second))
	frame := authFrame(c.key, carrierQUIC, exp, c.session)
	if err = writeFull(l, frame[:]); err != nil {
		return nil, err
	}
	_ = l.CloseWrite()
	s.CancelRead(0)
	success = true
	go q.run()
	return q, nil
}
func (c *Client) acquire(ctx context.Context, carrier byte, id uint32) (*lane, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if carrier == carrierQUIC {
		q, err := c.getQUIC(ctx)
		if err != nil {
			return nil, err
		}
		s, err := q.conn.OpenStreamSync(ctx)
		if err != nil {
			return nil, err
		}
		return &lane{&quicStream{Stream: s, conn: q.conn}, q}, nil
	}
	if !c.config.Mux {
		conn, err := c.dialTLS(ctx)
		if err != nil {
			return nil, err
		}
		return &lane{Conn: conn}, nil
	}
	s, err := c.acquireMux(ctx, id)
	if err != nil {
		return nil, err
	}
	return &lane{Conn: s}, nil
}
func (c *Client) routes() [][2]byte {
	choices := func(s string) []byte {
		if s == "tcp" {
			return []byte{carrierTLS}
		}
		if s == "udp" {
			return []byte{carrierQUIC}
		}
		return []byte{carrierTLS, carrierQUIC}
	}
	var routes [][2]byte
	if c.config.Up == "mix" && c.config.Down == "mix" {
		routes = [][2]byte{{1, 1}, {2, 2}}
	} else {
		for _, up := range choices(c.config.Up) {
			for _, down := range choices(c.config.Down) {
				routes = append(routes, [2]byte{up, down})
			}
		}
	}
	if len(routes) == 2 && c.route.Add(1)%2 == 0 {
		routes[0], routes[1] = routes[1], routes[0]
	}
	return routes
}
func (c *Client) reserve() (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	if len(c.flows) >= 4096 {
		return 0, SetupError(FlowLimit)
	}
	for {
		c.nextID = c.nextID%maxFlowID + 1
		if _, ok := c.flows[c.nextID]; !ok {
			c.flows[c.nextID] = nil
			return c.nextID, nil
		}
	}
}
func (c *Client) release(id uint32) { c.mu.Lock(); delete(c.flows, id); c.mu.Unlock() }
func (c *Client) establish(ctx context.Context, target string, udp bool) (*flowConn, *packetConn, error) {
	targetWire, err := targetBytes(target)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	stopClient := make(chan struct{})
	defer close(stopClient)
	go func() {
		select {
		case <-c.ctx.Done():
			cancel()
		case <-ctx.Done():
		case <-stopClient:
		}
	}()
	routes := c.routes()
	var f *flowConn
	var id uint32
	var route [2]byte
	for i, r := range routes {
		id, err = c.reserve()
		if err != nil {
			return nil, nil, err
		}
		route = r
		acquireCtx := ctx
		finish := func() {}
		if i < len(routes)-1 {
			acquireCtx, finish = context.WithTimeout(ctx, time.Second)
		}
		up, e := c.acquire(acquireCtx, r[0], id)
		var down *lane
		if e == nil {
			down = up
			if r[0] != r[1] {
				down, e = c.acquire(acquireCtx, r[1], id)
			}
		}
		finish()
		if e != nil {
			if up != nil {
				up.Close()
			}
			c.release(id)
			err = e
			continue
		}
		f = &flowConn{reader: down, writer: up, release: func() { c.release(id) }, done: make(chan struct{})}
		break
	}
	if f == nil {
		return nil, nil, err
	}
	if err = ctx.Err(); err != nil {
		f.Close()
		return nil, nil, err
	}
	stop := watch(ctx, f)
	defer stop()
	success := false
	defer func() {
		if !success {
			f.Close()
		}
	}()
	if d, ok := ctx.Deadline(); ok {
		_ = f.SetDeadline(d)
	}
	h := header{role: duplex, up: route[0], down: route[1], id: id, hops: Hops(ctx)}
	if udp {
		h.kind = 1
	}
	if route[0] != route[1] {
		h.role = open
	}
	// Fallback is forbidden once flow setup starts.
	if err = writeFull(f.writer, append(h.bytes(), targetWire...)); err != nil {
		return nil, nil, err
	}
	if h.role == open {
		h.role = attach
		if err = writeFull(f.reader, h.bytes()); err != nil {
			return nil, nil, err
		}
	}
	var p *packetConn
	if udp {
		p, err = newPacket(f, id, target, f.reader.q, f.writer.q)
		if err != nil {
			return nil, nil, err
		}
		for _, l := range f.lanes() {
			if l.q != nil {
				if err = l.Conn.(*quicStream).CloseWrite(); err != nil {
					p.Close()
					return nil, nil, err
				}
			}
		}
		defer func() {
			if !success {
				p.Close()
			}
		}()
	}
	if err = readResult(f.reader); err != nil {
		return nil, nil, err
	}
	_ = f.SetDeadline(time.Time{})
	if p != nil {
		if err = p.prepare(); err != nil {
			return nil, nil, err
		}
		p.start()
	}
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return nil, nil, net.ErrClosed
	}
	c.flows[id] = f
	c.mu.Unlock()
	f.watchCarriers()
	success = true
	return f, p, nil
}
func (c *Client) DialContext(ctx context.Context, target string) (net.Conn, error) {
	f, _, err := c.establish(ctx, target, false)
	return f, err
}
func (c *Client) ListenPacket(ctx context.Context, target string) (net.PacketConn, error) {
	_, p, err := c.establish(ctx, target, true)
	return p, err
}
