package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/quic-go"

	D "github.com/miekg/dns"
)

const NextProtoDQ = "doq"
const (
	// QUICCodeNoError is used when the connection or stream needs to be closed,
	// but there is no error to signal.
	QUICCodeNoError = quic.ApplicationErrorCode(0)
	// QUICCodeInternalError signals that the DoQ implementation encountered
	// an internal error and is incapable of pursuing the transaction or the
	// connection.
	QUICCodeInternalError = quic.ApplicationErrorCode(1)
	// QUICKeepAlivePeriod is the value that we pass to *quic.Config and that
	// controls the period with with keep-alive frames are being sent to the
	// connection. We set it to 20s as it would be in the quic-go@v0.27.1 with
	// KeepAlive field set to true This value is specified in
	// https://pkg.go.dev/github.com/metacubex/quic-go/internal/protocol#MaxKeepAliveInterval.
	//
	// TODO(ameshkov):  Consider making it configurable.
	QUICKeepAlivePeriod = time.Second * 20
	DefaultTimeout      = time.Second * 5
)

// dnsOverQUIC is a struct that implements the Upstream interface for the
// DNS-over-QUIC protocol (spec: https://www.rfc-editor.org/rfc/rfc9250.html).
type dnsOverQUIC struct {
	// quicConfig is the QUIC configuration that is used for establishing
	// connections to the upstream.  This configuration includes the TokenStore
	// that needs to be stored for the lifetime of dnsOverQUIC since we can
	// re-create the connection.
	quicConfig      *quic.Config
	quicConfigGuard sync.Mutex

	// conn is the current active QUIC connection.  It can be closed and
	// re-opened when needed.
	conn   quic.Connection
	connMu sync.RWMutex

	// bytesPool is a *sync.Pool we use to store byte buffers in.  These byte
	// buffers are used to read responses from the upstream.
	bytesPool      *sync.Pool
	bytesPoolGuard sync.Mutex

	addr         string
	proxyAdapter C.ProxyAdapter
	proxyName    string
	r            *Resolver
}

// type check
var _ dnsClient = (*dnsOverQUIC)(nil)

// newDoQ returns the DNS-over-QUIC Upstream.
func newDoQ(resolver *Resolver, addr string, proxyAdapter C.ProxyAdapter, proxyName string) (dnsClient, error) {
	doq := &dnsOverQUIC{
		addr:         addr,
		proxyAdapter: proxyAdapter,
		proxyName:    proxyName,
		r:            resolver,
		quicConfig: &quic.Config{
			KeepAlivePeriod: QUICKeepAlivePeriod,
			TokenStore:      newQUICTokenStore(),
		},
	}

	runtime.SetFinalizer(doq, (*dnsOverQUIC).Close)
	return doq, nil
}

// Address implements the Upstream interface for *dnsOverQUIC.
func (doq *dnsOverQUIC) Address() string { return doq.addr }

func (doq *dnsOverQUIC) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	// When sending queries over a QUIC connection, the DNS Message ID MUST be
	// set to zero.
	m = m.Copy()
	id := m.Id
	m.Id = 0
	defer func() {
		// Restore the original ID to not break compatibility with proxies.
		m.Id = id
		if msg != nil {
			msg.Id = id
		}
	}()

	// Check if there was already an active conn before sending the request.
	// We'll only attempt to re-connect if there was one.
	hasConnection := doq.hasConnection()

	// Make the first attempt to send the DNS query.
	msg, err = doq.exchangeQUIC(ctx, m)

	// Make up to 2 attempts to re-open the QUIC connection and send the request
	// again.  There are several cases where this workaround is necessary to
	// make DoQ usable.  We need to make 2 attempts in the case when the
	// connection was closed (due to inactivity for example) AND the server
	// refuses to open a 0-RTT connection.
	for i := 0; hasConnection && doq.shouldRetry(err) && i < 2; i++ {
		log.Debugln("re-creating the QUIC connection and retrying due to %v", err)

		// Close the active connection to make sure we'll try to re-connect.
		doq.closeConnWithError(err)

		// Retry sending the request.
		msg, err = doq.exchangeQUIC(ctx, m)
	}

	if err != nil {
		// If we're unable to exchange messages, make sure the connection is
		// closed and signal about an internal error.
		doq.closeConnWithError(err)
	}

	return msg, err
}

// Close implements the Upstream interface for *dnsOverQUIC.
func (doq *dnsOverQUIC) Close() (err error) {
	doq.connMu.Lock()
	defer doq.connMu.Unlock()

	runtime.SetFinalizer(doq, nil)

	if doq.conn != nil {
		err = doq.conn.CloseWithError(QUICCodeNoError, "")
	}

	return err
}

// exchangeQUIC attempts to open a QUIC connection, send the DNS message
// through it and return the response it got from the server.
func (doq *dnsOverQUIC) exchangeQUIC(ctx context.Context, msg *D.Msg) (resp *D.Msg, err error) {
	var conn quic.Connection
	conn, err = doq.getConnection(ctx, true)
	if err != nil {
		return nil, err
	}

	var buf []byte
	buf, err = msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message for DoQ: %w", err)
	}

	var stream quic.Stream
	stream, err = doq.openStream(ctx, conn)
	if err != nil {
		return nil, err
	}

	_, err = stream.Write(AddPrefix(buf))
	if err != nil {
		return nil, fmt.Errorf("failed to write to a QUIC stream: %w", err)
	}

	// The client MUST send the DNS query over the selected stream, and MUST
	// indicate through the STREAM FIN mechanism that no further data will
	// be sent on that stream. Note, that stream.Close() closes the
	// write-direction of the stream, but does not prevent reading from it.
	_ = stream.Close()

	return doq.readMsg(stream)
}

// AddPrefix adds a 2-byte prefix with the DNS message length.
func AddPrefix(b []byte) (m []byte) {
	m = make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(m, uint16(len(b)))
	copy(m[2:], b)

	return m
}

// shouldRetry checks what error we received and decides whether it is required
// to re-open the connection and retry sending the request.
func (doq *dnsOverQUIC) shouldRetry(err error) (ok bool) {
	return isQUICRetryError(err)
}

// getBytesPool returns (creates if needed) a pool we store byte buffers in.
func (doq *dnsOverQUIC) getBytesPool() (pool *sync.Pool) {
	doq.bytesPoolGuard.Lock()
	defer doq.bytesPoolGuard.Unlock()

	if doq.bytesPool == nil {
		doq.bytesPool = &sync.Pool{
			New: func() interface{} {
				b := make([]byte, MaxMsgSize)

				return &b
			},
		}
	}

	return doq.bytesPool
}

// getConnection opens or returns an existing quic.Connection. useCached
// argument controls whether we should try to use the existing cached
// connection.  If it is false, we will forcibly create a new connection and
// close the existing one if needed.
func (doq *dnsOverQUIC) getConnection(ctx context.Context, useCached bool) (quic.Connection, error) {
	var conn quic.Connection
	doq.connMu.RLock()
	conn = doq.conn
	if conn != nil && useCached {
		doq.connMu.RUnlock()

		return conn, nil
	}
	if conn != nil {
		// we're recreating the connection, let's create a new one.
		_ = conn.CloseWithError(QUICCodeNoError, "")
	}
	doq.connMu.RUnlock()

	doq.connMu.Lock()
	defer doq.connMu.Unlock()

	var err error
	conn, err = doq.openConnection(ctx)
	if err != nil {
		return nil, err
	}
	doq.conn = conn

	return conn, nil
}

// hasConnection returns true if there's an active QUIC connection.
func (doq *dnsOverQUIC) hasConnection() (ok bool) {
	doq.connMu.Lock()
	defer doq.connMu.Unlock()

	return doq.conn != nil
}

// getQUICConfig returns the QUIC config in a thread-safe manner.  Note, that
// this method returns a pointer, it is forbidden to change its properties.
func (doq *dnsOverQUIC) getQUICConfig() (c *quic.Config) {
	doq.quicConfigGuard.Lock()
	defer doq.quicConfigGuard.Unlock()

	return doq.quicConfig
}

// resetQUICConfig re-creates the tokens store as we may need to use a new one
// if we failed to connect.
func (doq *dnsOverQUIC) resetQUICConfig() {
	doq.quicConfigGuard.Lock()
	defer doq.quicConfigGuard.Unlock()

	doq.quicConfig = doq.quicConfig.Clone()
	doq.quicConfig.TokenStore = newQUICTokenStore()
}

// openStream opens a new QUIC stream for the specified connection.
func (doq *dnsOverQUIC) openStream(ctx context.Context, conn quic.Connection) (quic.Stream, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := conn.OpenStreamSync(ctx)
	if err == nil {
		return stream, nil
	}

	// We can get here if the old QUIC connection is not valid anymore.  We
	// should try to re-create the connection again in this case.
	newConn, err := doq.getConnection(ctx, false)
	if err != nil {
		return nil, err
	}
	// Open a new stream.
	return newConn.OpenStreamSync(ctx)
}

// openConnection opens a new QUIC connection.
func (doq *dnsOverQUIC) openConnection(ctx context.Context) (conn quic.Connection, err error) {
	// we're using bootstrapped address instead of what's passed to the function
	// it does not create an actual connection, but it helps us determine
	// what IP is actually reachable (when there're v4/v6 addresses).
	rawConn, err := getDialHandler(doq.r, doq.proxyAdapter, doq.proxyName)(ctx, "udp", doq.addr)
	if err != nil {
		return nil, fmt.Errorf("failed to open a QUIC connection: %w", err)
	}
	addr := rawConn.RemoteAddr().String()
	// It's never actually used
	_ = rawConn.Close()

	ip, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	p, err := strconv.Atoi(port)
	udpAddr := net.UDPAddr{IP: net.ParseIP(ip), Port: p}
	udp, err := listenPacket(ctx, doq.proxyAdapter, doq.proxyName, "udp", addr, doq.r)
	if err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(doq.addr)
	if err != nil {
		return nil, err
	}

	tlsConfig := ca.GetGlobalTLSConfig(
		&tls.Config{
			ServerName:         host,
			InsecureSkipVerify: false,
			NextProtos: []string{
				NextProtoDQ,
			},
			SessionTicketsDisabled: false,
		})

	transport := quic.Transport{Conn: udp}
	transport.SetCreatedConn(true) // auto close conn
	transport.SetSingleUse(true)   // auto close transport
	conn, err = transport.Dial(ctx, &udpAddr, tlsConfig, doq.getQUICConfig())
	if err != nil {
		return nil, fmt.Errorf("opening quic connection to %s: %w", doq.addr, err)
	}

	return conn, nil
}

// closeConnWithError closes the active connection with error to make sure that
// new queries were processed in another connection.  We can do that in the case
// of a fatal error.
func (doq *dnsOverQUIC) closeConnWithError(err error) {
	doq.connMu.Lock()
	defer doq.connMu.Unlock()

	if doq.conn == nil {
		// Do nothing, there's no active conn anyways.
		return
	}

	code := QUICCodeNoError
	if err != nil {
		code = QUICCodeInternalError
	}

	if errors.Is(err, quic.Err0RTTRejected) {
		// Reset the TokenStore only if 0-RTT was rejected.
		doq.resetQUICConfig()
	}

	err = doq.conn.CloseWithError(code, "")
	if err != nil {
		log.Errorln("failed to close the conn: %v", err)
	}
	doq.conn = nil
}

// readMsg reads the incoming DNS message from the QUIC stream.
func (doq *dnsOverQUIC) readMsg(stream quic.Stream) (m *D.Msg, err error) {
	pool := doq.getBytesPool()
	bufPtr := pool.Get().(*[]byte)

	defer pool.Put(bufPtr)

	respBuf := *bufPtr
	n, err := stream.Read(respBuf)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("reading response from %s: %w", doq.Address(), err)
	}

	// All DNS messages (queries and responses) sent over DoQ connections MUST
	// be encoded as a 2-octet length field followed by the message content as
	// specified in [RFC1035].
	// IMPORTANT: Note, that we ignore this prefix here as this implementation
	// does not support receiving multiple messages over a single connection.
	m = new(D.Msg)
	err = m.Unpack(respBuf[2:])
	if err != nil {
		return nil, fmt.Errorf("unpacking response from %s: %w", doq.Address(), err)
	}

	return m, nil
}

// newQUICTokenStore creates a new quic.TokenStore that is necessary to have
// in order to benefit from 0-RTT.
func newQUICTokenStore() (s quic.TokenStore) {
	// You can read more on address validation here:
	// https://datatracker.ietf.org/doc/html/rfc9000#section-8.1
	// Setting maxOrigins to 1 and tokensPerOrigin to 10 assuming that this is
	// more than enough for the way we use it (one connection per upstream).
	return quic.NewLRUTokenStore(1, 10)
}

// isQUICRetryError checks the error and determines whether it may signal that
// we should re-create the QUIC connection.  This requirement is caused by
// quic-go issues, see the comments inside this function.
// TODO(ameshkov): re-test when updating quic-go.
func isQUICRetryError(err error) (ok bool) {
	var qAppErr *quic.ApplicationError
	if errors.As(err, &qAppErr) && qAppErr.ErrorCode == 0 {
		// This error is often returned when the server has been restarted,
		// and we try to use the same connection on the client-side. It seems,
		// that the old connections aren't closed immediately on the server-side
		// and that's why one can run into this.
		// In addition to that, quic-go HTTP3 client implementation does not
		// clean up dead connections (this one is specific to DoH3 upstream):
		// https://github.com/metacubex/quic-go/issues/765
		return true
	}

	var qIdleErr *quic.IdleTimeoutError
	if errors.As(err, &qIdleErr) {
		// This error means that the connection was closed due to being idle.
		// In this case we should forcibly re-create the QUIC connection.
		// Reproducing is rather simple, stop the server and wait for 30 seconds
		// then try to send another request via the same upstream.
		return true
	}

	var resetErr *quic.StatelessResetError
	if errors.As(err, &resetErr) {
		// A stateless reset is sent when a server receives a QUIC packet that
		// it doesn't know how to decrypt.  For instance, it may happen when
		// the server was recently rebooted.  We should reconnect and try again
		// in this case.
		return true
	}

	var qTransportError *quic.TransportError
	if errors.As(err, &qTransportError) && qTransportError.ErrorCode == quic.NoError {
		// A transport error with the NO_ERROR error code could be sent by the
		// server when it considers that it's time to close the connection.
		// For example, Google DNS eventually closes an active connection with
		// the NO_ERROR code and "Connection max age expired" message:
		// https://github.com/AdguardTeam/dnsproxy/issues/283
		return true
	}

	if errors.Is(err, quic.Err0RTTRejected) {
		// This error happens when we try to establish a 0-RTT connection with
		// a token the server is no more aware of.  This can be reproduced by
		// restarting the QUIC server (it will clear its tokens cache).  The
		// next connection attempt will return this error until the client's
		// tokens cache is purged.
		return true
	}

	return false
}
