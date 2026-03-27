package xhttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/contextutils"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

type DialRawFunc func(ctx context.Context) (net.Conn, error)
type WrapTLSFunc func(ctx context.Context, conn net.Conn, isH2 bool) (net.Conn, error)

type PacketUpConn struct {
	ctx        context.Context
	cfg        *Config
	address    string
	port       int
	host       string
	sessionID  string
	client     *http.Client
	writeMu    sync.Mutex
	seq        uint64
	reader     io.ReadCloser
	remoteAddr net.Addr
	localAddr  net.Addr
}

type stringAddr struct {
	network string
	addr    string
}

func (a stringAddr) Network() string { return a.network }
func (a stringAddr) String() string  { return a.addr }

func (c *PacketUpConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *PacketUpConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	u := url.URL{
		Scheme: "https",
		Host:   c.host,
		Path:   c.cfg.NormalizedPath(),
	}

	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return 0, err
	}

	seqStr := strconv.FormatUint(c.seq, 10)
	c.seq++

	if err := c.cfg.FillPacketRequest(req, c.sessionID, seqStr, b); err != nil {
		return 0, err
	}
	req.Host = c.host

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("xhttp packet-up bad status: %s", resp.Status)
	}

	return len(b), nil
}

func (c *PacketUpConn) Close() error {
	if c.reader != nil {
		return c.reader.Close()
	}
	return nil
}

func (c *PacketUpConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *PacketUpConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *PacketUpConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *PacketUpConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *PacketUpConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func DialStreamOne(
	ctx context.Context,
	address string,
	port int,
	cfg *Config,
	dialRaw DialRawFunc,
	wrapTLS WrapTLSFunc,
) (net.Conn, error) {
	remoteAddr := stringAddr{
		network: "tcp",
		addr:    net.JoinHostPort(address, strconv.Itoa(port)),
	}

	host := cfg.Host
	if host == "" {
		host = address
	}

	requestURL := url.URL{
		Scheme: "https",
		Host:   host,
		Path:   cfg.NormalizedPath(),
	}

	transport := &http.Http2Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			raw, err := dialRaw(ctx)
			if err != nil {
				return nil, err
			}
			wrapped, err := wrapTLS(ctx, raw, true)
			if err != nil {
				_ = raw.Close()
				return nil, err
			}
			return wrapped, nil
		},
	}

	client := &http.Client{
		Transport: transport,
	}

	pr, pw := io.Pipe()

	req, err := http.NewRequestWithContext(contextutils.WithoutCancel(ctx), http.MethodPost, requestURL.String(), pr)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	req.Host = host

	if err := cfg.FillStreamRequest(req); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}

	type respResult struct {
		resp *http.Response
		err  error
	}

	respCh := make(chan respResult, 1)

	go func() {
		resp, err := client.Do(req)
		respCh <- respResult{resp: resp, err: err}
	}()

	result := <-respCh
	if result.err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, result.err
	}
	if result.resp.StatusCode < 200 || result.resp.StatusCode >= 300 {
		_ = result.resp.Body.Close()
		_ = pr.Close()
		_ = pw.Close()
		return nil, fmt.Errorf("xhttp stream-one bad status: %s", result.resp.Status)
	}

	return &Conn{
		writer:     pw,
		reader:     result.resp.Body,
		remoteAddr: remoteAddr,
		localAddr:  remoteAddr,
		onClose: func() {
			_ = result.resp.Body.Close()
			_ = pr.Close()
		},
	}, nil
}

func DialPacketUp(
	ctx context.Context,
	address string,
	port int,
	cfg *Config,
	dialRaw DialRawFunc,
	wrapTLS WrapTLSFunc,
) (net.Conn, error) {
	remoteAddr := stringAddr{
		network: "tcp",
		addr:    net.JoinHostPort(address, strconv.Itoa(port)),
	}

	host := cfg.Host
	if host == "" {
		host = address
	}

	transport := &http.Http2Transport{
		DialTLSContext: func(ctx context.Context, network string, addr string, _ *tls.Config) (net.Conn, error) {
			raw, err := dialRaw(ctx)
			if err != nil {
				return nil, err
			}
			wrapped, err := wrapTLS(ctx, raw, true)
			if err != nil {
				_ = raw.Close()
				return nil, err
			}
			return wrapped, nil
		},
	}

	client := &http.Client{Transport: transport}

	sessionID := newSessionID()

	downloadURL := url.URL{
		Scheme: "https",
		Host:   host,
		Path:   cfg.NormalizedPath(),
	}

	req, err := http.NewRequestWithContext(contextutils.WithoutCancel(ctx), http.MethodGet, downloadURL.String(), nil)
	if err != nil {
		return nil, err
	}
	if err := cfg.FillDownloadRequest(req, sessionID); err != nil {
		return nil, err
	}
	req.Host = host

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("xhttp packet-up download bad status: %s", resp.Status)
	}

	return &PacketUpConn{
		ctx:        contextutils.WithoutCancel(ctx),
		cfg:        cfg,
		address:    address,
		port:       port,
		host:       host,
		sessionID:  sessionID,
		client:     client,
		seq:        0,
		reader:     resp.Body,
		remoteAddr: remoteAddr,
		localAddr:  remoteAddr,
	}, nil
}

func newSessionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
