package miu

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/transport/anytls/padding"

	M "github.com/metacubex/sing/common/metadata"
)

const (
	authHead = 32 + 2 // token · padlen

	defaultIdleTimeout = 180 * time.Second
	// defaultHandshakeTimeout: as long as web servers wait for a request (nginx's client_header_timeout),
	// so that a connection that sends nothing is closed when theirs would be. A client's warm lane may
	// also stay silent this long before its first use.
	defaultHandshakeTimeout = 60 * time.Second
	// settingsWait is how long ServerSettings waits for the lane's next write to go out with. The client
	// needs it only once its stream is past the inner handshake, which starts with the server's first
	// downlink write; until then it would be a short record of its own.
	settingsWait       = time.Second
	defaultDialTimeout = 10 * time.Second

	// pskMinLen is the shortest PSK string accepted.
	pskMinLen = 16
)

// ErrAuth is returned by Server.Serve when a connection presents an unknown token.
var ErrAuth = errors.New("miu: auth failed: unknown token")

// Handler takes over one stream a client has opened: conn carries the stream's payload and destination
// is where the client wants it to go (uot.RequestDestination for UDP over the stream). The stream ends
// when Handler returns. conn also has a CloseWrite method.
type Handler func(ctx context.Context, conn net.Conn, user string, destination M.Socksaddr)

// ServerConfig configures a Server. Users and Handler are required.
type ServerConfig struct {
	// Users maps a user name to its PSK.
	Users map[string]string
	// PaddingScheme overrides the built-in scheme; clients with a different one are sent this one.
	PaddingScheme string
	// IdleTimeout is how long a lane without a stream is kept (default 180s). Clients are told.
	IdleTimeout time.Duration
	// HandshakeTimeout bounds the wait for the authentication header (default 60s).
	HandshakeTimeout time.Duration
	// Fallback, when set, is the address (host:port) of a web server that gets every connection that is
	// not a client: the bytes already read, then everything that follows, both ways. Without it such a
	// connection is read and dropped until HandshakeTimeout, and then closed. Only the outer TLS of the
	// Miu server faces these connections; with REALITY they never get this far.
	Fallback string
	// DisableRaw turns raw segments off: the server declares raw=0 and never sends any.
	DisableRaw bool
	Handler    Handler
}

// Server serves lanes: connections on which the outer TLS handshake has already been done.
type Server struct {
	cfg    ServerConfig
	users  map[[32]byte]string
	scheme *padding.PaddingFactory
}

// pskToken is the authentication token of a PSK: the SHA-256 of the string with surrounding whitespace
// removed. The string is not base64-decoded.
func pskToken(psk string) ([32]byte, error) {
	psk = strings.TrimSpace(psk)
	if len(psk) < pskMinLen {
		return [32]byte{}, fmt.Errorf("miu: psk too short (need at least %d characters)", pskMinLen)
	}
	return sha256.Sum256([]byte(psk)), nil
}

func NewServer(cfg ServerConfig) (*Server, error) {
	s := &Server{cfg: cfg, users: make(map[[32]byte]string, len(cfg.Users))}
	if len(cfg.Users) == 0 {
		return nil, errors.New("miu: no users")
	}
	if cfg.Handler == nil {
		return nil, errors.New("miu: no handler")
	}
	for name, psk := range cfg.Users {
		token, err := pskToken(psk)
		if err != nil {
			return nil, fmt.Errorf("user %q: %w", name, err)
		}
		if _, dup := s.users[token]; dup {
			return nil, fmt.Errorf("miu: user %q shares its psk with another user", name)
		}
		s.users[token] = name
	}
	scheme := padding.DefaultPaddingScheme
	if cfg.PaddingScheme != "" {
		scheme = []byte(cfg.PaddingScheme)
	}
	if s.scheme = padding.NewPaddingFactory(scheme); s.scheme == nil {
		return nil, errors.New("miu: bad padding scheme")
	}
	if s.cfg.IdleTimeout <= 0 {
		s.cfg.IdleTimeout = defaultIdleTimeout
	}
	if s.cfg.HandshakeTimeout <= 0 {
		s.cfg.HandshakeTimeout = defaultHandshakeTimeout
	}
	return s, nil
}

// Serve serves one lane until the client closes it, it has been idle for too long, or ctx is done.
// conn is the connection after the outer TLS handshake; raw segments are available when it is a Go TLS
// connection (see tlsBuffers) sitting directly on the TCP connection. Serve closes conn before returning.
//
// A nil error means the lane ended normally. ErrAuth and protocol violations are reported as errors.
func (s *Server) Serve(ctx context.Context, conn net.Conn) error {
	defer conn.Close()
	user, token, err := s.authenticate(ctx, conn)
	if err != nil {
		return err
	}

	l := newLane(conn, true, !s.cfg.DisableRaw)
	// Each lane gets its own idle timeout, so that lane lifetimes do not all end at the same mark.
	l.idle = jitter(s.cfg.IdleTimeout, 0.85)
	base := s.scheme
	if s.cfg.PaddingScheme == "" {
		derived, err := derivedScheme(token)
		if err != nil {
			return err
		}
		base = padding.NewPaddingFactory([]byte(derived))
		l.scheme.Store(newLaneScheme(token, base)) // this lane's own draw, for the downlink
	} else {
		l.scheme.Store(base)
	}
	l.base = base
	// cur is the stream on the lane (the last one, once it has ended); nil before the first OPEN.
	// However the lane ends, that stream ends with it.
	var cur atomic.Pointer[serverStream]
	stop := func() {
		l.close()
		if st := cur.Load(); st != nil {
			st.laneClosed()
		}
	}
	defer stop()
	go func() {
		select {
		case <-ctx.Done():
			stop()
		case <-l.done:
		}
	}()

	// There is a single frame reading loop. It queues the uplink of a stream (DATA / RAW / END) for the
	// handler, which writes the downlink from its own goroutine, and it keeps reading after the
	// uplink's END — which is how a RESET sent after a half-close still gets through.
	_ = conn.SetReadDeadline(time.Now().Add(l.idle))
	for {
		typ, payload, err := l.next()
		if err != nil {
			return nil // the client left, the lane idled out, or a failed downlink write closed it
		}
		st := cur.Load()
		switch typ {
		case frData, frRaw:
			if st == nil || st.upEnded {
				return errors.New("miu: data outside of a stream")
			}
			for l.pending() {
				buf := pool.Get(pool.RelayBufferSize)
				n, err := l.readPayload(buf)
				if err != nil {
					_ = pool.Put(buf)
					return nil
				}
				st.push(buf[:n])
			}
		case frEnd, frReset:
			if len(payload) != 0 {
				return errors.New("miu: bad END / RESET frame")
			}
			if st == nil {
				continue
			}
			if typ == frReset {
				// Abort: the downlink stops and ends with END. The lane lives on. A RESET that arrives
				// after its stream has ended finds nothing left to abort.
				st.reset()
			}
			st.endUplink()
		case frSettings:
			if err := s.handleSettings(l, string(payload)); err != nil {
				return nil
			}
		case frOpen:
			if st != nil {
				if !st.upEnded {
					return errors.New("miu: OPEN before the previous stream ended")
				}
				// The client sends the next OPEN only after it has seen the downlink's END; wait for
				// the stream to have recorded that it sent it.
				select {
				case <-st.done:
				case <-l.done:
					return nil
				}
			}
			r := bytes.NewReader(payload)
			destination, err := M.SocksaddrSerializer.ReadAddrPort(r)
			if err != nil || r.Len() != 0 {
				return errors.New("miu: bad destination in OPEN")
			}
			_ = conn.SetReadDeadline(time.Time{})
			st = newServerStream(l, l.idle, isUoT(destination))
			cur.Store(st)
			go func() {
				defer st.Close()
				s.cfg.Handler(ctx, st, user, destination)
			}()
		default:
			return fmt.Errorf("miu: unexpected frame type %d", typ)
		}
	}
}

// authenticate reads the authentication header — token(32) · padlen(u16) · padding — exactly, never
// ahead, and returns the name of the user the token belongs to. A connection that is not a client is
// dealt with here (notAClient) and reported as ErrAuth.
func (s *Server) authenticate(ctx context.Context, conn net.Conn) (string, [32]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	var h [authHead]byte
	n, err := readAuthHead(conn, h[:])
	var token [32]byte
	copy(token[:], h[:])
	user, ok := "", false
	if n == authHead {
		user, ok = s.users[token]
	}
	if !ok {
		s.notAClient(ctx, conn, h[:n])
		if n < authHead && err != nil {
			return "", [32]byte{}, fmt.Errorf("miu: auth failed: %w", err)
		}
		return "", [32]byte{}, ErrAuth
	}
	if padlen := int64(binary.BigEndian.Uint16(h[32:])); padlen > 0 {
		if _, err := io.CopyN(io.Discard, conn, padlen); err != nil {
			return "", [32]byte{}, fmt.Errorf("miu: auth failed: %w", err)
		}
	}
	return user, token, nil
}

// readAuthHead reads the authentication header into h. Over TLS a single Read returns at most the rest
// of the current record, and a client writes the header together with its padding and Settings: a first
// record shorter than the header does not come from a client, and there is no point waiting for more.
func readAuthHead(conn net.Conn, h []byte) (int, error) {
	// Any of the TLS implementations in use (crypto/tls, metacubex/tls, REALITY) has ConnectionState.
	if !reflect.ValueOf(conn).MethodByName("ConnectionState").IsValid() {
		return io.ReadFull(conn, h)
	}
	return conn.Read(h)
}

// notAClient deals with a connection that did not present a valid header: it goes to the fallback web
// server (consumed first) when there is one; otherwise what it sends is read and dropped until the
// handshake deadline. Either way it is answered the way something other than Miu would answer it.
func (s *Server) notAClient(ctx context.Context, conn net.Conn, consumed []byte) {
	if s.cfg.Fallback == "" {
		_, _ = io.Copy(io.Discard, conn)
		return
	}
	d := net.Dialer{Timeout: defaultDialTimeout}
	back, err := d.DialContext(ctx, "tcp", s.cfg.Fallback)
	if err != nil {
		_, _ = io.Copy(io.Discard, conn)
		return
	}
	defer back.Close()
	_ = conn.SetReadDeadline(time.Time{})
	if len(consumed) > 0 {
		if _, err := back.Write(consumed); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(back, conn)
		if cw, ok := back.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, back)
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = conn.Close()
		}
		done <- struct{}{}
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
	_ = conn.Close()
	_ = back.Close()
	<-done
}

// handleSettings notes whether the client can receive raw segments and answers with ServerSettings,
// followed by the scheme the client's lanes should come from when its md5 is not that of the lane's
// base (the PSK-derived scheme, or the configured one). The answer goes out at the start of the next
// write on the lane, or alone after settingsWait.
func (s *Server) handleSettings(l *lane, text string) error {
	kv := parseKV(text)
	l.peerRaw.Store(kv["raw"] == "1")
	reply := appendFrame(nil, frServerSettings, l.settingsText(fmt.Sprintf("\nidle=%d", int(l.idle/time.Second))))
	base := l.base
	if base == nil {
		base = l.scheme.Load()
	}
	if md5 := strings.ToLower(strings.TrimSpace(kv["padding-md5"])); md5 != "" && md5 != base.Md5 {
		reply = appendFrame(reply, frUpdatePadding, base.RawScheme)
	}
	l.deferPrefix(reply, settingsWait)
	return nil
}
