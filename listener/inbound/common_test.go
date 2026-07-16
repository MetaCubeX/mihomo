package inbound_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/ech"
	"github.com/metacubex/mihomo/component/generator"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/assert"
)

var httpPath = "/inbound_test"
var httpData = make([]byte, 2*pool.RelayBufferSize)
var remoteAddr = netip.MustParseAddr("1.2.3.4")
var userUUID = utils.NewUUIDV4().String()
var tlsCertificate, tlsPrivateKey, tlsFingerprint, _ = ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
var tlsAuthCertificate, tlsAuthPrivateKey, _, _ = ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
var tlsConfigCert, _ = tls.X509KeyPair([]byte(tlsCertificate), []byte(tlsPrivateKey))
var tlsConfig = &tls.Config{Certificates: []tls.Certificate{tlsConfigCert}, NextProtos: []string{"h2", "http/1.1"}}
var realityTLSConfig = newRealityCarrierTLSConfig()
var tlsClientConfig, _ = ca.GetTLSConfig(ca.Option{Fingerprint: tlsFingerprint})
var realityPrivateKey, realityPublickey string
var realityDest = "itunes.apple.com"
var realityShortid = "10f897e26c4b9478"
var realityRealDial = false
var echPublicSni = "public.sni"
var echConfigBase64, echKeyPem, _ = ech.GenECHConfig(echPublicSni)
var winGo120 = runtime.GOOS == "windows" && strings.HasPrefix(runtime.Version(), "go1.20")

func init() {
	rand.Read(httpData)
	privateKey, err := generator.GenX25519PrivateKey()
	if err != nil {
		panic(err)
	}
	realityPrivateKey = base64.RawURLEncoding.EncodeToString(privateKey.Bytes())
	realityPublickey = base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())
}

func newRealityCarrierTLSConfig() *tls.Config {
	certificate := tlsConfigCert
	leaf := append([]byte(nil), certificate.Certificate[0]...)
	for chainBytes := len(leaf); chainBytes < 6*1024; chainBytes += len(leaf) {
		certificate.Certificate = append(certificate.Certificate, append([]byte(nil), leaf...))
	}
	return &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2", "http/1.1"}}
}

type TestDialer struct {
	dialer C.Dialer
	ctx    context.Context
}

func (t *TestDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
start:
	conn, err := t.dialer.DialContext(ctx, network, address)
	if err != nil && ctx.Err() == nil && t.ctx.Err() == nil {
		// We are conducting tests locally, and they shouldn't fail.
		// However, a large number of requests in a short period during concurrent testing can exhaust system ports.
		// This can lead to various errors such as WSAECONNREFUSED and WSAENOBUFS.
		// So we just retry if the context is not canceled.
		goto start
	}
	return conn, err
}

func (t *TestDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	return t.dialer.ListenPacket(ctx, network, address, rAddrPort)
}

var _ C.Dialer = (*TestDialer)(nil)

type TestTunnel struct {
	HandleTCPConnFn    func(conn net.Conn, metadata *C.Metadata)
	HandleUDPPacketFn  func(packet C.UDPPacket, metadata *C.Metadata)
	NatTableFn         func() C.NatTable
	CloseFn            func() error
	DoSequentialTestFn func(t *testing.T, proxy C.ProxyAdapter)
	DoConcurrentTestFn func(t *testing.T, proxy C.ProxyAdapter)
	NewDialerFn        func() C.Dialer
}

func (tt *TestTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	tt.HandleTCPConnFn(conn, metadata)
}

func (tt *TestTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	tt.HandleUDPPacketFn(packet, metadata)
}

func (tt *TestTunnel) NatTable() C.NatTable {
	return tt.NatTableFn()
}

func (tt *TestTunnel) Close() error {
	return tt.CloseFn()
}

func (tt *TestTunnel) DoTest(t *testing.T, proxy C.ProxyAdapter) {
	tt.DoSequentialTestFn(t, proxy)
	tt.DoConcurrentTestFn(t, proxy)
}

func (tt *TestTunnel) DoSequentialTest(t *testing.T, proxy C.ProxyAdapter) {
	tt.DoSequentialTestFn(t, proxy)
}

func (tt *TestTunnel) DoConcurrentTest(t *testing.T, proxy C.ProxyAdapter) {
	tt.DoConcurrentTestFn(t, proxy)
}

func (tt *TestTunnel) NewDialer() C.Dialer {
	return tt.NewDialerFn()
}

type TestTunnelListener struct {
	ch     chan net.Conn
	ctx    context.Context
	cancel context.CancelFunc
	addr   net.Addr
}

func (t *TestTunnelListener) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-t.ch:
		if !ok {
			return nil, net.ErrClosed
		}
		return conn, nil
	case <-t.ctx.Done():
		return nil, t.ctx.Err()
	}
}

func (t *TestTunnelListener) Close() error {
	t.cancel()
	return nil
}

func (t *TestTunnelListener) Addr() net.Addr {
	return t.addr
}

type WaitCloseConn struct {
	net.Conn
	ch   chan struct{}
	once sync.Once
}

func (c *WaitCloseConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		close(c.ch)
	})
	return err
}

var _ C.Tunnel = (*TestTunnel)(nil)
var _ net.Listener = (*TestTunnelListener)(nil)

func NewHttpTestTunnel() *TestTunnel {
	ctx, cancel := context.WithCancel(context.Background())
	ln := &TestTunnelListener{ch: make(chan net.Conn), ctx: ctx, cancel: cancel, addr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(remoteAddr, 0))}

	r := chi.NewRouter()
	r.Post(httpPath, func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		size, err := strconv.Atoi(query.Get("size"))
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.PlainText(w, r, err.Error())
			return
		}
		io.Copy(io.Discard, r.Body)
		render.Data(w, r, httpData[:size])
	})
	//h2Server := &http.Http2Server{}
	server := http.Server{Handler: r}
	//_ = http.Http2ConfigureServer(&server, h2Server)
	go server.Serve(ln)
	testFn := func(t *testing.T, proxy C.ProxyAdapter, proto string, size int) {
		req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s://%s%s?size=%d", proto, remoteAddr, httpPath, size), bytes.NewReader(httpData[:size]))
		if !assert.NoError(t, err) {
			return
		}
		req = req.WithContext(ctx)

		var dstPort uint16 = 80
		if proto == "https" {
			dstPort = 443
		}
		metadata := &C.Metadata{
			NetWork: C.TCP,
			DstIP:   remoteAddr,
			DstPort: dstPort,
		}
		instance, err := proxy.DialContext(ctx, metadata)
		if !assert.NoError(t, err) {
			return
		}
		defer instance.Close()

		var dialNum atomic.Int32
		var extraConns []net.Conn
		var extraConnsMu sync.Mutex
		defer func() {
			extraConnsMu.Lock()
			extraConns := append([]net.Conn{}, extraConns...) // clone conn list avoid race condition
			extraConnsMu.Unlock()
			for _, conn := range extraConns {
				_ = conn.Close()
			}
		}()

		transport := &http.Transport{
			DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
				dianNum := dialNum.Add(1)
				if dianNum == 1 { // first dial, return instance
					return instance, nil
				}
				t.Logf("transport dial time %d more than once in: %s", dianNum, t.Name())
				conn, err := proxy.DialContext(ctx, metadata)
				if err != nil {
					return nil, err
				}
				extraConnsMu.Lock()
				extraConns = append(extraConns, conn)
				extraConnsMu.Unlock()
				return conn, nil
			},
			//// from http.DefaultTransport
			//MaxIdleConns:          100,
			//IdleConnTimeout:       90 * time.Second,
			//TLSHandshakeTimeout:   10 * time.Second,
			//ExpectContinueTimeout: 1 * time.Second,
			// for our self-signed cert
			TLSClientConfig: tlsClientConfig.Clone(),
			// open http2
			ForceAttemptHTTP2: true,
		}

		client := http.Client{
			Timeout:   60 * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		defer client.CloseIdleConnections()

		resp, err := client.Do(req)
		if !assert.NoError(t, err) {
			return
		}

		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		if proto == "https" { // ensure server using http2
			assert.Equal(t, 2, resp.ProtoMajor)
		}

		data, err := io.ReadAll(resp.Body)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, httpData[:size], data)
	}

	sequentialTestFn := func(t *testing.T, proxy C.ProxyAdapter) {
		// Sequential testing for debugging
		t.Run("Sequential", func(t *testing.T) {
			testFn(t, proxy, "http", len(httpData))
			testFn(t, proxy, "https", len(httpData))
		})
	}

	concurrentTestFn := func(t *testing.T, proxy C.ProxyAdapter) {
		// Concurrent testing to detect stress
		t.Run("Concurrent", func(t *testing.T) {
			if skip, _ := strconv.ParseBool(os.Getenv("SKIP_CONCURRENT_TEST")); skip {
				t.Skip("skip concurrent test")
			}
			wg := sync.WaitGroup{}
			num := len(httpData) / 1024
			for i := 1; i <= num; i++ {
				i := i
				wg.Add(1)
				go func() {
					testFn(t, proxy, "https", i*1024)
					defer wg.Done()
				}()
			}
			for i := 1; i <= num; i++ {
				i := i
				wg.Add(1)
				go func() {
					testFn(t, proxy, "http", i*1024)
					defer wg.Done()
				}()
			}
			wg.Wait()
		})
	}

	tunnel := &TestTunnel{
		HandleTCPConnFn: func(conn net.Conn, metadata *C.Metadata) {
			defer conn.Close()
			if metadata.DstIP != remoteAddr && metadata.Host != realityDest {
				return // not match, just return
			}
			c := &WaitCloseConn{
				Conn: conn,
				ch:   make(chan struct{}),
			}
			if metadata.DstPort == 443 {
				serverTLSConfig := tlsConfig
				if metadata.Host == realityDest {
					serverTLSConfig = realityTLSConfig
				}
				tlsConn := tls.Server(c, serverTLSConfig)
				if metadata.Host == realityDest { // ignore the tls handshake error for realityDest
					if realityRealDial {
						rconn, err := dialer.DialContext(ctx, "tcp", metadata.RemoteAddress())
						if err != nil {
							panic(err)
						}
						N.Relay(rconn, conn)
						return
					}
				}
				//ctx, cancel := context.WithTimeout(ctx, C.DefaultTLSTimeout)
				//defer cancel()
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					return
				}
				//if tlsConn.ConnectionState().NegotiatedProtocol == http.Http2NextProtoTLS {
				//	h2Server.ServeConn(tlsConn, &http.Http2ServeConnOpts{BaseConfig: &server})
				//} else {
				//	ln.ch <- tlsConn
				//}
				ln.ch <- tlsConn
			} else {
				ln.ch <- c
			}
			<-c.ch
		},
		HandleUDPPacketFn: func(packet C.UDPPacket, metadata *C.Metadata) {
			// TODO
		},
		CloseFn:            ln.Close,
		DoSequentialTestFn: sequentialTestFn,
		DoConcurrentTestFn: concurrentTestFn,
		NewDialerFn:        func() C.Dialer { return &TestDialer{dialer: dialer.NewDialer(), ctx: ctx} },
	}
	return tunnel
}
