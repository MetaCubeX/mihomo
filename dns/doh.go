package dns

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
	D "github.com/miekg/dns"
	"golang.org/x/exp/slices"
)

// Values to configure HTTP and HTTP/2 transport.
const (
	// transportDefaultReadIdleTimeout is the default timeout for pinging
	// idle connections in HTTP/2 transport.
	transportDefaultReadIdleTimeout = 30 * time.Second

	// transportDefaultIdleConnTimeout is the default timeout for idle
	// connections in HTTP transport.
	transportDefaultIdleConnTimeout = 5 * time.Minute

	// dohMaxConnsPerHost controls the maximum number of connections for
	// each host.  Note, that setting it to 1 may cause issues with Go's http
	// implementation, see https://github.com/AdguardTeam/dnsproxy/issues/278.
	dohMaxConnsPerHost = 2
	dialTimeout        = 10 * time.Second

	// dohMaxIdleConns controls the maximum number of connections being idle
	// at the same time.
	dohMaxIdleConns = 2
	maxElapsedTime  = time.Second * 30
)

var DefaultHTTPVersions = []C.HTTPVersion{C.HTTPVersion11, C.HTTPVersion2}

// dnsOverHTTPS is a struct that implements the Upstream interface for the
// DNS-over-HTTPS protocol.
type dnsOverHTTPS struct {
	// The Client's Transport typically has internal state (cached TCP
	// connections), so Clients should be reused instead of created as
	// needed. Clients are safe for concurrent use by multiple goroutines.
	client   *http.Client
	clientMu sync.Mutex

	// quicConfig is the QUIC configuration that is used if HTTP/3 is enabled
	// for this upstream.
	quicConfig      *quic.Config
	quicConfigGuard sync.Mutex

	url            *url.URL
	httpVersions   []C.HTTPVersion
	dialer         *dnsDialer
	addr           string
	skipCertVerify bool
}

// type check
var _ dnsClient = (*dnsOverHTTPS)(nil)

// newDoH returns the DNS-over-HTTPS Upstream.
func newDoHClient(urlString string, r *Resolver, preferH3 bool, params map[string]string, proxyAdapter C.ProxyAdapter, proxyName string) dnsClient {
	u, _ := url.Parse(urlString)
	httpVersions := DefaultHTTPVersions
	if preferH3 {
		httpVersions = append(httpVersions, C.HTTPVersion3)
	}

	if params["h3"] == "true" {
		httpVersions = []C.HTTPVersion{C.HTTPVersion3}
	}

	doh := &dnsOverHTTPS{
		url:    u,
		addr:   u.String(),
		dialer: newDNSDialer(r, proxyAdapter, proxyName),
		quicConfig: &quic.Config{
			KeepAlivePeriod: QUICKeepAlivePeriod,
			TokenStore:      newQUICTokenStore(),
		},
		httpVersions: httpVersions,
	}

	if params["skip-cert-verify"] == "true" {
		doh.skipCertVerify = true
	}

	runtime.SetFinalizer(doh, (*dnsOverHTTPS).Close)

	return doh
}

// Address implements the Upstream interface for *dnsOverHTTPS.
func (doh *dnsOverHTTPS) Address() string {
	return doh.addr
}

func (doh *dnsOverHTTPS) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	// Quote from https://www.rfc-editor.org/rfc/rfc8484.html:
	// In order to maximize HTTP cache friendliness, DoH clients using media
	// formats that include the ID field from the DNS message header, such
	// as "application/dns-message", SHOULD use a DNS ID of 0 in every DNS
	// request.
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

	// Check if there was already an active client before sending the request.
	// We'll only attempt to re-connect if there was one.
	client, isCached, err := doh.getClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to init http client: %w", err)
	}

	// Make the first attempt to send the DNS query.
	msg, err = doh.exchangeHTTPS(ctx, client, m)

	// Make up to 2 attempts to re-create the HTTP client and send the request
	// again.  There are several cases (mostly, with QUIC) where this workaround
	// is necessary to make HTTP client usable.  We need to make 2 attempts in
	// the case when the connection was closed (due to inactivity for example)
	// AND the server refuses to open a 0-RTT connection.
	for i := 0; isCached && doh.shouldRetry(err) && i < 2; i++ {
		client, err = doh.resetClient(ctx, err)
		if err != nil {
			return nil, fmt.Errorf("failed to reset http client: %w", err)
		}

		msg, err = doh.exchangeHTTPS(ctx, client, m)
	}

	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		// If the request failed anyway, make sure we don't use this client.
		_, resErr := doh.resetClient(ctx, err)

		return nil, fmt.Errorf("%w (resErr:%v)", err, resErr)
	}

	return msg, err
}

// Close implements the Upstream interface for *dnsOverHTTPS.
func (doh *dnsOverHTTPS) Close() (err error) {
	doh.clientMu.Lock()
	defer doh.clientMu.Unlock()

	runtime.SetFinalizer(doh, nil)

	if doh.client == nil {
		return nil
	}

	return doh.closeClient(doh.client)
}

func (doh *dnsOverHTTPS) ResetConnection() {
	doh.clientMu.Lock()
	defer doh.clientMu.Unlock()

	if doh.client == nil {
		return
	}

	_ = doh.closeClient(doh.client)
	doh.client = nil
}

// closeClient cleans up resources used by client if necessary.
func (doh *dnsOverHTTPS) closeClient(client *http.Client) (err error) {
	client.CloseIdleConnections()

	if isHTTP3(client) { // HTTP/3 may leak due to keep-alive connections.
		return client.Transport.(io.Closer).Close()
	}

	return nil
}

// exchangeHTTPS sends the DNS query to a DoH resolver using the specified
// http.Client instance.
func (doh *dnsOverHTTPS) exchangeHTTPS(ctx context.Context, client *http.Client, req *D.Msg) (resp *D.Msg, err error) {
	buf, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing message: %w", err)
	}

	// It appears, that GET requests are more memory-efficient with Golang
	// implementation of HTTP/2.
	method := http.MethodGet
	if isHTTP3(client) {
		// If we're using HTTP/3, use http3.MethodGet0RTT to force using 0-RTT.
		method = http3.MethodGet0RTT
	}

	requestUrl := *doh.url // don't modify origin url
	requestUrl.RawQuery = fmt.Sprintf("dns=%s", base64.RawURLEncoding.EncodeToString(buf))
	httpReq, err := http.NewRequestWithContext(ctx, method, requestUrl.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating http request to %s: %w", doh.url, err)
	}

	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("User-Agent", "")
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("requesting %s: %w", doh.url, err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", doh.url, err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil,
			fmt.Errorf(
				"expected status %d, got %d from %s",
				http.StatusOK,
				httpResp.StatusCode,
				doh.url,
			)
	}

	resp = &D.Msg{}
	err = resp.Unpack(body)
	if err != nil {
		return nil, fmt.Errorf(
			"unpacking response from %s: body is %s: %w",
			doh.url,
			body,
			err,
		)
	}

	if resp.Id != req.Id {
		err = D.ErrId
	}

	return resp, err
}

// shouldRetry checks what error we have received and returns true if we should
// re-create the HTTP client and retry the request.
func (doh *dnsOverHTTPS) shouldRetry(err error) (ok bool) {
	if err == nil {
		return false
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		// If this is a timeout error, trying to forcibly re-create the HTTP
		// client instance.  This is an attempt to fix an issue with DoH client
		// stalling after a network change.
		//
		// See https://github.com/AdguardTeam/AdGuardHome/issues/3217.
		return true
	}

	if isQUICRetryError(err) {
		return true
	}

	return false
}

// resetClient triggers re-creation of the *http.Client that is used by this
// upstream.  This method accepts the error that caused resetting client as
// depending on the error we may also reset the QUIC config.
func (doh *dnsOverHTTPS) resetClient(ctx context.Context, resetErr error) (client *http.Client, err error) {
	doh.clientMu.Lock()
	defer doh.clientMu.Unlock()

	if errors.Is(resetErr, quic.Err0RTTRejected) {
		// Reset the TokenStore only if 0-RTT was rejected.
		doh.resetQUICConfig()
	}

	oldClient := doh.client
	if oldClient != nil {
		closeErr := doh.closeClient(oldClient)
		if closeErr != nil {
			log.Warnln("warning: failed to close the old http client: %v", closeErr)
		}
	}

	log.Debugln("re-creating the http client due to %v", resetErr)
	doh.client, err = doh.createClient(ctx)

	return doh.client, err
}

// getQUICConfig returns the QUIC config in a thread-safe manner.  Note, that
// this method returns a pointer, it is forbidden to change its properties.
func (doh *dnsOverHTTPS) getQUICConfig() (c *quic.Config) {
	doh.quicConfigGuard.Lock()
	defer doh.quicConfigGuard.Unlock()

	return doh.quicConfig
}

// resetQUICConfig Re-create the token store to make sure we're not trying to
// use invalid for 0-RTT.
func (doh *dnsOverHTTPS) resetQUICConfig() {
	doh.quicConfigGuard.Lock()
	defer doh.quicConfigGuard.Unlock()

	doh.quicConfig = doh.quicConfig.Clone()
	doh.quicConfig.TokenStore = newQUICTokenStore()
}

// getClient gets or lazily initializes an HTTP client (and transport) that will
// be used for this DoH resolver.
func (doh *dnsOverHTTPS) getClient(ctx context.Context) (c *http.Client, isCached bool, err error) {
	startTime := time.Now()

	doh.clientMu.Lock()
	defer doh.clientMu.Unlock()
	if doh.client != nil {
		return doh.client, true, nil
	}

	// Timeout can be exceeded while waiting for the lock. This happens quite
	// often on mobile devices.
	elapsed := time.Since(startTime)
	if elapsed > maxElapsedTime {
		return nil, false, fmt.Errorf("timeout exceeded: %s", elapsed)
	}

	log.Debugln("creating a new http client")
	doh.client, err = doh.createClient(ctx)

	return doh.client, false, err
}

// createClient creates a new *http.Client instance.  The HTTP protocol version
// will depend on whether HTTP3 is allowed and provided by this upstream.  Note,
// that we'll attempt to establish a QUIC connection when creating the client in
// order to check whether HTTP3 is supported.
func (doh *dnsOverHTTPS) createClient(ctx context.Context) (*http.Client, error) {
	transport, err := doh.createTransport(ctx)
	if err != nil {
		return nil, fmt.Errorf("[%s] initializing http transport: %w", doh.url.String(), err)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   DefaultTimeout,
		Jar:       nil,
	}

	doh.client = client

	return doh.client, nil
}

// createTransport initializes an HTTP transport that will be used specifically
// for this DoH resolver.  This HTTP transport ensures that the HTTP requests
// will be sent exactly to the IP address got from the bootstrap resolver. Note,
// that this function will first attempt to establish a QUIC connection (if
// HTTP3 is enabled in the upstream options).  If this attempt is successful,
// it returns an HTTP3 transport, otherwise it returns the H1/H2 transport.
func (doh *dnsOverHTTPS) createTransport(ctx context.Context) (t http.RoundTripper, err error) {
	transport := &http.Transport{
		DisableCompression: true,
		DialContext:        doh.dialer.DialContext,
		IdleConnTimeout:    transportDefaultIdleConnTimeout,
		MaxConnsPerHost:    dohMaxConnsPerHost,
		MaxIdleConns:       dohMaxIdleConns,
	}

	if doh.url.Scheme == "http" {
		return transport, nil
	}

	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			InsecureSkipVerify:     doh.skipCertVerify,
			MinVersion:             tls.VersionTLS12,
			SessionTicketsDisabled: false,
		},
	})
	if err != nil {
		return nil, err
	}
	var nextProtos []string
	for _, v := range doh.httpVersions {
		nextProtos = append(nextProtos, string(v))
	}
	tlsConfig.NextProtos = nextProtos
	transport.TLSClientConfig = tlsConfig

	if slices.Contains(doh.httpVersions, C.HTTPVersion3) {
		// First, we attempt to create an HTTP3 transport.  If the probe QUIC
		// connection is established successfully, we'll be using HTTP3 for this
		// upstream.
		transportH3, err := doh.createTransportH3(ctx, tlsConfig)
		if err == nil {
			log.Debugln("[%s] using HTTP/3 for this upstream: QUIC was faster", doh.url.String())
			return transportH3, nil
		}
	}

	log.Debugln("[%s] using HTTP/2 for this upstream: %v", doh.url.String(), err)

	if !doh.supportsHTTP() {
		return nil, errors.New("HTTP1/1 and HTTP2 are not supported by this upstream")
	}

	// Since we have a custom DialContext, we need to use this field to
	// make golang http.Client attempt to use HTTP/2. Otherwise, it would
	// only be used when negotiated on the TLS level.
	transport.ForceAttemptHTTP2 = true

	// Explicitly configure transport to use HTTP/2.
	//
	// See https://github.com/AdguardTeam/dnsproxy/issues/11.
	var transportH2 *http.Http2Transport
	transportH2, err = http.Http2ConfigureTransports(transport)
	if err != nil {
		return nil, err
	}

	// Enable HTTP/2 pings on idle connections.
	transportH2.ReadIdleTimeout = transportDefaultReadIdleTimeout

	return transport, nil
}

// http3Transport is a wrapper over *http3.Transport that tries to optimize
// its behavior.  The main thing that it does is trying to force use a single
// connection to a host instead of creating a new one all the time.  It also
// helps mitigate race issues with quic-go.
type http3Transport struct {
	baseTransport *http3.Transport

	closed bool
	mu     sync.RWMutex
}

// type check
var _ http.RoundTripper = (*http3Transport)(nil)

// RoundTrip implements the http.RoundTripper interface for *http3Transport.
func (h *http3Transport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.closed {
		return nil, net.ErrClosed
	}

	// Try to use cached connection to the target host if it's available.
	resp, err = h.baseTransport.RoundTripOpt(req, http3.RoundTripOpt{OnlyCachedConn: true})

	if errors.Is(err, http3.ErrNoCachedConn) {
		// If there are no cached connection, trigger creating a new one.
		resp, err = h.baseTransport.RoundTrip(req)
	}

	return resp, err
}

// type check
var _ io.Closer = (*http3Transport)(nil)

// Close implements the io.Closer interface for *http3Transport.
func (h *http3Transport) Close() (err error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.closed = true

	return h.baseTransport.Close()
}

func (h *http3Transport) CloseIdleConnections() {
	h.mu.RLock()
	defer h.mu.RUnlock()

	h.baseTransport.CloseIdleConnections()
}

// createTransportH3 tries to create an HTTP/3 transport for this upstream.
// We should be able to fall back to H1/H2 in case if HTTP/3 is unavailable or
// if it is too slow.  In order to do that, this method will run two probes
// in parallel (one for TLS, the other one for QUIC) and if QUIC is faster it
// will create the *http3.Transport instance.
func (doh *dnsOverHTTPS) createTransportH3(
	ctx context.Context,
	tlsConfig *tls.Config,
) (roundTripper http.RoundTripper, err error) {
	if !doh.supportsH3() {
		return nil, errors.New("HTTP3 support is not enabled")
	}

	addr, err := doh.probeH3(ctx, tlsConfig)
	if err != nil {
		return nil, err
	}

	rt := &http3.Transport{
		Dial: func(
			ctx context.Context,

			// Ignore the address and always connect to the one that we got
			// from the bootstrapper.
			_ string,
			tlsCfg *tls.Config,
			cfg *quic.Config,
		) (c *quic.Conn, err error) {
			return doh.dialQuic(ctx, addr, tlsCfg, cfg)
		},
		DisableCompression: true,
		TLSClientConfig:    tlsConfig,
		QUICConfig:         doh.getQUICConfig(),
	}

	return &http3Transport{baseTransport: rt}, nil
}

func (doh *dnsOverHTTPS) dialQuic(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	ip, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}
	udpAddr := net.UDPAddr{
		IP:   net.ParseIP(ip),
		Port: portInt,
	}
	conn, err := doh.dialer.ListenPacket(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	transport := quic.Transport{Conn: conn}
	transport.SetCreatedConn(true) // auto close conn
	transport.SetSingleUse(true)   // auto close transport
	tlsCfg = tlsCfg.Clone()
	if host, _, err := net.SplitHostPort(doh.url.Host); err == nil {
		tlsCfg.ServerName = host
	} else {
		// It's ok if net.SplitHostPort returns an error - it could be a hostname/IP address without a port.
		tlsCfg.ServerName = doh.url.Host
	}
	return transport.DialEarly(ctx, &udpAddr, tlsCfg, cfg)
}

// probeH3 runs a test to check whether QUIC is faster than TLS for this
// upstream.  If the test is successful it will return the address that we
// should use to establish the QUIC connections.
func (doh *dnsOverHTTPS) probeH3(
	ctx context.Context,
	tlsConfig *tls.Config,
) (addr string, err error) {
	// We're using bootstrapped address instead of what's passed to the function
	// it does not create an actual connection, but it helps us determine
	// what IP is actually reachable (when there are v4/v6 addresses).
	rawConn, err := doh.dialer.DialContext(ctx, "udp", doh.url.Host)
	if err != nil {
		return "", fmt.Errorf("failed to dial: %w", err)
	}
	addr = rawConn.RemoteAddr().String()
	// It's never actually used.
	_ = rawConn.Close()

	// Avoid spending time on probing if this upstream only supports HTTP/3.
	if doh.supportsH3() && !doh.supportsHTTP() {
		return addr, nil
	}

	// Use a new *tls.Config with empty session cache for probe connections.
	// Surprisingly, this is really important since otherwise it invalidates
	// the existing cache.
	// TODO(ameshkov): figure out why the sessions cache invalidates here.
	probeTLSCfg := tlsConfig.Clone()
	probeTLSCfg.ClientSessionCache = nil

	// Do not expose probe connections to the callbacks that are passed to
	// the bootstrap options to avoid side-effects.
	// TODO(ameshkov): consider exposing, somehow mark that this is a probe.
	probeTLSCfg.VerifyPeerCertificate = nil
	probeTLSCfg.VerifyConnection = nil

	// Run probeQUIC and probeTLS in parallel and see which one is faster.
	chQuic := make(chan error, 1)
	chTLS := make(chan error, 1)
	go doh.probeQUIC(ctx, addr, probeTLSCfg, chQuic)
	go doh.probeTLS(ctx, probeTLSCfg, chTLS)

	select {
	case quicErr := <-chQuic:
		if quicErr != nil {
			// QUIC failed, return error since HTTP3 was not preferred.
			return "", quicErr
		}

		// Return immediately, QUIC was faster.
		return addr, quicErr
	case tlsErr := <-chTLS:
		if tlsErr != nil {
			// Return immediately, TLS failed.
			log.Debugln("probing TLS: %v", tlsErr)
			return addr, nil
		}

		return "", errors.New("TLS was faster than QUIC, prefer it")
	}
}

// probeQUIC attempts to establish a QUIC connection to the specified address.
// We run probeQUIC and probeTLS in parallel and see which one is faster.
func (doh *dnsOverHTTPS) probeQUIC(ctx context.Context, addr string, tlsConfig *tls.Config, ch chan error) {
	startTime := time.Now()
	conn, err := doh.dialQuic(ctx, addr, tlsConfig, doh.getQUICConfig())
	if err != nil {
		ch <- fmt.Errorf("opening QUIC connection to %s: %w", doh.Address(), err)
		return
	}

	// Ignore the error since there's no way we can use it for anything useful.
	_ = conn.CloseWithError(QUICCodeNoError, "")

	ch <- nil

	elapsed := time.Now().Sub(startTime)
	log.Debugln("elapsed on establishing a QUIC connection: %s", elapsed)
}

// probeTLS attempts to establish a TLS connection to the specified address. We
// run probeQUIC and probeTLS in parallel and see which one is faster.
func (doh *dnsOverHTTPS) probeTLS(ctx context.Context, tlsConfig *tls.Config, ch chan error) {
	startTime := time.Now()

	conn, err := doh.tlsDial(ctx, "tcp", tlsConfig)
	if err != nil {
		ch <- fmt.Errorf("opening TLS connection: %w", err)
		return
	}

	// Ignore the error since there's no way we can use it for anything useful.
	_ = conn.Close()

	ch <- nil

	elapsed := time.Now().Sub(startTime)
	log.Debugln("elapsed on establishing a TLS connection: %s", elapsed)
}

// supportsH3 returns true if HTTP/3 is supported by this upstream.
func (doh *dnsOverHTTPS) supportsH3() (ok bool) {
	for _, v := range doh.supportedHTTPVersions() {
		if v == C.HTTPVersion3 {
			return true
		}
	}

	return false
}

// supportsHTTP returns true if HTTP/1.1 or HTTP2 is supported by this upstream.
func (doh *dnsOverHTTPS) supportsHTTP() (ok bool) {
	for _, v := range doh.supportedHTTPVersions() {
		if v == C.HTTPVersion11 || v == C.HTTPVersion2 {
			return true
		}
	}

	return false
}

// supportedHTTPVersions returns the list of supported HTTP versions.
func (doh *dnsOverHTTPS) supportedHTTPVersions() (v []C.HTTPVersion) {
	v = doh.httpVersions
	if v == nil {
		v = DefaultHTTPVersions
	}

	return v
}

// isHTTP3 checks if the *http.Client is an HTTP/3 client.
func isHTTP3(client *http.Client) (ok bool) {
	_, ok = client.Transport.(*http3Transport)

	return ok
}

// tlsDial is basically the same as tls.DialWithDialer, but we will call our own
// dialContext function to get connection.
func (doh *dnsOverHTTPS) tlsDial(ctx context.Context, network string, config *tls.Config) (*tls.Conn, error) {
	// We're using bootstrapped address instead of what's passed
	// to the function.
	rawConn, err := doh.dialer.DialContext(ctx, network, doh.url.Host)
	if err != nil {
		return nil, err
	}

	// We want the timeout to cover the whole process: TCP connection and
	// TLS handshake dialTimeout will be used as connection deadLine.
	conn := tls.Client(rawConn, config)

	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	err = conn.HandshakeContext(ctx)
	if err != nil {
		defer conn.Close()
		return nil, err
	}

	return conn, nil
}
