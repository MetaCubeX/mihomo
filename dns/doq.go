package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
	"github.com/lucas-clemente/quic-go"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/Dreamacro/clash/log"
	D "github.com/miekg/dns"
)

const NextProtoDQ = "doq"

var bytesPool = sync.Pool{New: func() interface{} { return &bytes.Buffer{} }}

type quicClient struct {
	addr         string
	r            *Resolver
	session      quic.Connection
	proxyAdapter string
	sync.RWMutex // protects session and bytesPool
}

func newDOQ(r *Resolver, addr, proxyAdapter string) *quicClient {
	return &quicClient{
		addr:         addr,
		r:            r,
		proxyAdapter: proxyAdapter,
	}
}

func (dc *quicClient) Exchange(m *D.Msg) (msg *D.Msg, err error) {
	return dc.ExchangeContext(context.Background(), m)
}

func (dc *quicClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	stream, err := dc.openStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open new stream to %s", dc.addr)
	}

	buf, err := m.Pack()
	if err != nil {
		return nil, err
	}

	_, err = stream.Write(buf)
	if err != nil {
		return nil, err
	}

	// The client MUST send the DNS query over the selected stream, and MUST
	// indicate through the STREAM FIN mechanism that no further data will
	// be sent on that stream.
	// stream.Close() -- closes the write-direction of the stream.
	_ = stream.Close()

	respBuf := bytesPool.Get().(*bytes.Buffer)
	defer bytesPool.Put(respBuf)
	defer respBuf.Reset()

	n, err := respBuf.ReadFrom(stream)
	if err != nil && n == 0 {
		return nil, err
	}

	reply := new(D.Msg)
	err = reply.Unpack(respBuf.Bytes())
	if err != nil {
		return nil, err
	}

	return reply, nil
}

func isActive(s quic.Connection) bool {
	select {
	case <-s.Context().Done():
		return false
	default:
		return true
	}
}

// getSession - opens or returns an existing quic.Connection
// useCached - if true and cached session exists, return it right away
// otherwise - forcibly creates a new session
func (dc *quicClient) getSession(ctx context.Context) (quic.Connection, error) {
	var session quic.Connection
	dc.RLock()
	session = dc.session
	if session != nil && isActive(session) {
		dc.RUnlock()
		return session, nil
	}
	if session != nil {
		// we're recreating the session, let's create a new one
		_ = session.CloseWithError(0, "")
	}
	dc.RUnlock()

	dc.Lock()
	defer dc.Unlock()

	var err error
	session, err = dc.openSession(ctx)
	if err != nil {
		// This does not look too nice, but QUIC (or maybe quic-go)
		// doesn't seem stable enough.
		// Maybe retransmissions aren't fully implemented in quic-go?
		// Anyways, the simple solution is to make a second try when
		// it fails to open the QUIC session.
		session, err = dc.openSession(ctx)
		if err != nil {
			return nil, err
		}
	}
	dc.session = session
	return session, nil
}

func (dc *quicClient) openSession(ctx context.Context) (quic.Connection, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		NextProtos: []string{
			NextProtoDQ,
		},
		SessionTicketsDisabled: false,
	}
	quicConfig := &quic.Config{
		ConnectionIDLength:   12,
		HandshakeIdleTimeout: time.Second * 8,
		MaxIncomingStreams:   4,
		MaxIdleTimeout:       time.Second * 45,
	}

	log.Debugln("opening session to %s", dc.addr)
	var (
		udp net.PacketConn
		err error
	)

	host, port, err := net.SplitHostPort(dc.addr)

	if err != nil {
		return nil, err
	}

	ip, err := resolver.ResolveIPv4WithResolver(host, dc.r)
	if err != nil {
		return nil, err
	}

	p, err := strconv.Atoi(port)
	udpAddr := net.UDPAddr{IP: ip.AsSlice(), Port: p}

	if dc.proxyAdapter == "" {
		udp, err = dialer.ListenPacket(ctx, "udp", "")
		if err != nil {
			return nil, err
		}
	} else {
		conn, err := dialContextExtra(ctx, dc.proxyAdapter, "udp", ip, port)
		if err != nil {
			return nil, err
		}

		wrapConn, ok := conn.(*wrapPacketConn)
		if !ok {
			return nil, fmt.Errorf("quic create packet failed")
		}

		udp = wrapConn
	}

	session, err := quic.DialContext(ctx, udp, &udpAddr, host, tlsConfig, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to open QUIC session: %w", err)
	}

	return session, nil
}

func (dc *quicClient) openStream(ctx context.Context) (quic.Stream, error) {
	session, err := dc.getSession(ctx)
	if err != nil {
		return nil, err
	}

	// open a new stream
	return session.OpenStreamSync(ctx)
}
