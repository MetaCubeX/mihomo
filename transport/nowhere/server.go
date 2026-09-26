package nowhere

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	quic "github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

type Handler interface {
	HandleTCP(context.Context, *ServerConn, string)
	HandleUDP(context.Context, *ServerPacketConn, string, net.Addr)
}
type ServerConfig struct {
	Password  string
	Morph     bool
	TLSConfig *tls.Config
	Handler   Handler
}
type claimKey struct {
	session [16]byte
	id      uint32
}
type claim struct {
	h        header
	up, down *lane
	target   string
	done     chan struct{}
	timer    *time.Timer
	started  bool
	rejected byte
	once     sync.Once
}
type Server struct {
	config    ServerConfig
	key       [32]byte
	morph     *morphKeys
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	closed    bool
	claims    map[claimKey]*claim
	counts    map[[16]byte]int
	quics     map[[16]byte]*quicSession
	resources map[io.Closer]struct{}
	admission chan struct{}
	setups    chan struct{}
	wg        sync.WaitGroup
}

func NewServer(config ServerConfig) (*Server, error) {
	key, err := authKey(config.Password)
	if err != nil {
		return nil, err
	}
	if config.TLSConfig == nil || config.Handler == nil {
		return nil, errors.New("nowhere: missing TLS configuration or handler")
	}
	config.TLSConfig = config.TLSConfig.Clone()
	config.TLSConfig.MinVersion = tls.VersionTLS13
	config.TLSConfig.NextProtos = []string{ALPN}
	s := &Server{config: config, key: key, claims: make(map[claimKey]*claim), counts: make(map[[16]byte]int), quics: make(map[[16]byte]*quicSession), resources: make(map[io.Closer]struct{}), admission: make(chan struct{}, 4096)}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.setups = make(chan struct{}, 1024)
	if config.Morph {
		s.morph = newMorphKeys(config.Password)
	}
	return s, nil
}
func (s *Server) track(c io.Closer) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		c.Close()
		return false
	}
	s.resources[c] = struct{}{}
	return true
}
func (s *Server) untrack(c io.Closer) { s.mu.Lock(); delete(s.resources, c); s.mu.Unlock() }
func (s *Server) launch(fn func()) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.wg.Add(1)
	go func() { defer s.wg.Done(); fn() }()
	return true
}
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.cancel()
	resources := make([]io.Closer, 0, len(s.resources))
	for r := range s.resources {
		resources = append(resources, r)
	}
	claims := make([]*claim, 0, len(s.claims))
	for _, c := range s.claims {
		claims = append(claims, c)
	}
	s.claims = make(map[claimKey]*claim)
	s.counts = make(map[[16]byte]int)
	s.resources = make(map[io.Closer]struct{})
	s.quics = make(map[[16]byte]*quicSession)
	s.mu.Unlock()
	for _, r := range resources {
		r.Close()
	}
	for _, c := range claims {
		c.once.Do(func() {
			if c.timer != nil {
				c.timer.Stop()
			}
			if c.up != nil {
				c.up.Close()
			}
			if c.down != nil && c.down != c.up {
				c.down.Close()
			}
			close(c.done)
		})
	}
	s.wg.Wait()
	return nil
}
func (s *Server) ServeTCP(l net.Listener) error {
	if !s.track(l) {
		return net.ErrClosed
	}
	if !s.launch(func() {
		defer s.untrack(l)
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			select {
			case s.admission <- struct{}{}:
			default:
				conn.Close()
				continue
			}
			if !s.track(conn) {
				<-s.admission
				return
			}
			if !s.launch(func() { defer func() { conn.Close(); s.untrack(conn); <-s.admission }(); s.acceptTLS(conn) }) {
				conn.Close()
				s.untrack(conn)
				<-s.admission
				return
			}
		}
	}) {
		return net.ErrClosed
	}
	return nil
}

type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }
func (c *bufferedConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return nil
}
func (s *Server) acceptTLS(raw net.Conn) {
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	conn := raw
	var err error
	if s.morph != nil {
		conn, err = wrapMorphTCP(raw, s.morph, false, false)
		if err != nil {
			return
		}
	}
	t := tls.Server(conn, s.config.TLSConfig)
	if t.HandshakeContext(s.ctx) != nil {
		return
	}
	exp, err := exporter(t.ConnectionState())
	if err != nil {
		return
	}
	session, err := readAuth(t, s.key, carrierTLS, exp)
	if err != nil {
		return
	}
	r := bufio.NewReader(t)
	b, err := r.Peek(1)
	if err != nil {
		return
	}
	conn = &bufferedConn{t, r}
	if b[0] == 255 {
		_, _ = r.ReadByte()
		_ = conn.SetDeadline(time.Time{})
		m := newMux(conn, func(stream *muxStream) {
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				stream.Close()
				return
			}
			s.wg.Add(1)
			s.mu.Unlock()
			defer s.wg.Done()
			s.handleLane(session, &lane{Conn: stream}, carrierTLS, stream.id)
		})
		<-m.done
		return
	}
	s.handleLane(session, &lane{Conn: conn}, carrierTLS, 0)
}
func (s *Server) ServeUDP(pc net.PacketConn) error {
	if s.morph != nil {
		pc = wrapMorphUDP(pc, s.morph, false)
	}
	if !s.track(pc) {
		return net.ErrClosed
	}
	cfg := quicConfig()
	if s.morph != nil {
		cfg.DisablePathMTUDiscovery = true
	}
	l, err := quic.Listen(pc, s.config.TLSConfig, cfg)
	if err != nil {
		pc.Close()
		s.untrack(pc)
		return err
	}
	if !s.track(l) {
		pc.Close()
		return net.ErrClosed
	}
	if !s.launch(func() {
		defer s.untrack(l)
		for {
			conn, err := l.Accept(s.ctx)
			if err != nil {
				return
			}
			select {
			case s.admission <- struct{}{}:
			default:
				conn.CloseWithError(1, "capacity")
				continue
			}
			q := newQUICSession(conn, nil)
			if !s.track(q) {
				<-s.admission
				return
			}
			if !s.launch(func() { defer func() { q.Close(); s.untrack(q); <-s.admission }(); s.acceptQUIC(q) }) {
				q.Close()
				s.untrack(q)
				<-s.admission
				return
			}
		}
	}) {
		return net.ErrClosed
	}
	return nil
}
func (s *Server) acceptQUIC(q *quicSession) {
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	first, err := q.conn.AcceptStream(ctx)
	if err != nil {
		return
	}
	_ = first.SetReadDeadline(time.Now().Add(10 * time.Second))
	exp, err := exporter(q.conn.ConnectionState().TLS)
	if err != nil {
		return
	}
	session, err := readAuth(first, s.key, carrierQUIC, exp)
	if err != nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	old := s.quics[session]
	s.quics[session] = q
	type staleClaim struct {
		key claimKey
		c   *claim
	}
	var stale []staleClaim
	if old != nil {
		for key, c := range s.claims {
			if key.session == session && !c.started && (c.up != nil && c.up.q == old || c.down != nil && c.down.q == old) {
				stale = append(stale, staleClaim{key, c})
			}
		}
	}
	s.mu.Unlock()
	if old != nil {
		for _, entry := range stale {
			s.fail(entry.key, entry.c, SessionReplaced)
		}
		old.Close()
	}
	defer func() {
		s.mu.Lock()
		if s.quics[session] == q {
			delete(s.quics, session)
		}
		s.mu.Unlock()
	}()
	go q.run()
	handle := func(stream *quic.Stream) {
		s.handleLane(session, &lane{&quicStream{Stream: stream, conn: q.conn}, q}, carrierQUIC, 0)
	}
	if !s.launch(func() { handle(first) }) {
		return
	}
	for {
		stream, err := q.conn.AcceptStream(s.ctx)
		if err != nil {
			return
		}
		if !s.launch(func() { handle(stream) }) {
			stream.CancelRead(0)
			stream.CancelWrite(0)
			return
		}
	}
}
func reject(l *lane, code byte) {
	_ = l.SetWriteDeadline(time.Now().Add(time.Second))
	_ = writeFull(l, []byte{code})
}
func (s *Server) handleLane(session [16]byte, l *lane, carrier byte, muxID uint32) {
	defer l.Close()
	select {
	case s.setups <- struct{}{}:
	default:
		reject(l, FlowLimit)
		return
	}
	setupHeld := true
	defer func() {
		if setupHeld {
			<-s.setups
		}
	}()
	_ = l.SetDeadline(time.Now().Add(10 * time.Second))
	h, err := readHeader(l)
	if err != nil {
		if err != io.EOF {
			reject(l, InvalidRequest)
		}
		return
	}
	if h.validate(carrier) != nil || muxID != 0 && muxID != h.id {
		s.rejectSetup(session, h, l, InvalidRequest)
		return
	}
	target := ""
	if h.role != attach {
		target, err = readTarget(l)
		if err != nil {
			s.rejectSetup(session, h, l, InvalidRequest)
			return
		}
	}
	key := claimKey{session, h.id}
	<-s.setups
	setupHeld = false
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if l.q != nil && s.quics[session] != l.q {
		s.mu.Unlock()
		s.rejectSetup(session, h, l, SessionReplaced)
		return
	}
	c := s.claims[key]
	if c != nil {
		if c.rejected != 0 {
			code := c.rejected
			s.mu.Unlock()
			if h.role != open {
				reject(l, code)
			}
			return
		}
		if c.started || h.role == duplex || h.role == open && c.up != nil || h.role == attach && c.down != nil {
			s.mu.Unlock()
			reject(l, MetadataConflict)
			return
		}
		if !c.h.matches(h) {
			s.mu.Unlock()
			reject(l, MetadataConflict)
			s.fail(key, c, MetadataConflict)
			return
		}
	} else {
		if len(s.claims) >= 65536 || s.counts[session] >= 4096 {
			s.mu.Unlock()
			reject(l, FlowLimit)
			return
		}
		c = &claim{h: h, done: make(chan struct{})}
		s.claims[key] = c
		s.counts[session]++
		c.timer = time.AfterFunc(10*time.Second, func() { s.fail(key, c, PairTimeout) })
	}
	if h.role == duplex {
		c.up = l
		c.down = l
		c.target = target
	} else if h.role == open {
		c.up = l
		c.target = target
	} else {
		c.down = l
	}
	complete := c.up != nil && c.down != nil
	if complete {
		c.started = true
		c.timer.Stop()
	}
	s.mu.Unlock()
	if complete {
		s.runFlow(key, c)
	} else {
		select {
		case <-c.done:
		case <-s.ctx.Done():
		}
	}
}
func (s *Server) remove(key claimKey, c *claim) {
	s.mu.Lock()
	if s.claims[key] == c {
		delete(s.claims, key)
		s.counts[key.session]--
		if s.counts[key.session] == 0 {
			delete(s.counts, key.session)
		}
	}
	s.mu.Unlock()
	c.once.Do(func() { c.timer.Stop(); close(c.done) })
}

func (s *Server) rejectSetup(session [16]byte, h header, l *lane, code byte) {
	if h.role != open {
		reject(l, code)
		return
	}
	key := claimKey{session, h.id}
	s.mu.Lock()
	c := s.claims[key]
	if c == nil && !s.closed && len(s.claims) < 65536 && s.counts[session] < 4096 {
		c = &claim{h: h, done: make(chan struct{})}
		s.claims[key] = c
		s.counts[session]++
		c.timer = time.AfterFunc(10*time.Second, func() { s.remove(key, c) })
	}
	s.mu.Unlock()
	if c != nil {
		s.fail(key, c, code)
	}
}
func (s *Server) fail(key claimKey, c *claim, code byte) {
	s.mu.Lock()
	if s.claims[key] != c || c.started || c.rejected != 0 {
		s.mu.Unlock()
		return
	}
	c.rejected = code
	down, up := c.down, c.up
	s.mu.Unlock()
	if down != nil {
		reject(down, code)
		down.Close()
	}
	if up != nil {
		up.Close()
	}
	c.once.Do(func() { close(c.done) })
	// Keep OPEN failures briefly so a later ATTACH receives the same result.
	time.AfterFunc(10*time.Second, func() { s.remove(key, c) })
}
func (s *Server) runFlow(key claimKey, c *claim) {
	f := &flowConn{reader: c.up, writer: c.down, release: func() { s.remove(key, c) }, done: make(chan struct{})}
	defer f.Close()
	f.watchCarriers()
	_ = f.SetDeadline(time.Time{})
	ctx := context.WithValue(s.ctx, hopsKey{}, c.h.hops)
	if c.h.kind == 0 {
		conn := &ServerConn{flowConn: f}
		defer conn.Close()
		s.config.Handler.HandleTCP(ctx, conn, c.target)
	} else {
		p, err := newPacket(f, c.h.id, c.target, c.up.q, c.down.q)
		if err != nil {
			reject(c.down, InternalError)
			return
		}
		conn := &ServerPacketConn{packetConn: p}
		defer conn.Close()
		s.config.Handler.HandleUDP(ctx, conn, c.target, c.up.RemoteAddr())
	}
}

// ServerConn leaves the setup result to the handler. Implementations must call
// HandshakeSuccess before reading or relaying application bytes.
type ServerConn struct {
	*flowConn
	resultOnce sync.Once
	resultErr  error
}

func (c *ServerConn) HandshakeSuccess() error {
	c.resultOnce.Do(func() { c.resultErr = writeFull(c.writer, []byte{Ready}) })
	return c.resultErr
}
func (c *ServerConn) HandshakeFailure(err error) error {
	c.resultOnce.Do(func() {
		_ = c.writer.SetWriteDeadline(time.Now().Add(time.Second))
		c.resultErr = writeFull(c.writer, []byte{failureCode(err)})
	})
	return c.resultErr
}
func (c *ServerConn) Close() error { _ = c.HandshakeFailure(net.ErrClosed); return c.flowConn.Close() }

func failureCode(err error) byte {
	var result SetupError
	if errors.As(err, &result) && result > 0 && byte(result) <= InternalError {
		return byte(result)
	}
	return DialFailed
}

// ServerPacketConn activates the wire flow when the handler accepts setup.
// QUIC payload received before READY is discarded.
type ServerPacketConn struct {
	*packetConn
	resultOnce sync.Once
	resultErr  error
}

func (c *ServerPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return c.packetConn.WriteTo(b, c.address)
}
func (c *ServerPacketConn) HandshakeSuccess() error {
	c.resultOnce.Do(func() {
		if err := c.prepare(); err != nil {
			reject(c.flow.writer, InternalError)
			c.resultErr = err
			return
		}
		c.resultErr = writeFull(c.flow.writer, []byte{Ready})
		if c.resultErr == nil {
			c.start()
		}
	})
	return c.resultErr
}
func (c *ServerPacketConn) HandshakeFailure(err error) error {
	c.resultOnce.Do(func() {
		_ = c.flow.writer.SetWriteDeadline(time.Now().Add(time.Second))
		c.resultErr = writeFull(c.flow.writer, []byte{failureCode(err)})
	})
	return c.resultErr
}
func (c *ServerPacketConn) Close() error {
	_ = c.HandshakeFailure(net.ErrClosed)
	return c.packetConn.Close()
}
