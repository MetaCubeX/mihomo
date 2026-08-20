package warp

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/metacubex/mihomo/common/contextutils"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"golang.org/x/sync/semaphore"
)

const L4ConnectSNI = "consumer-masque-proxy.cloudflareclient.com"

type DialQUICFunc func(ctx context.Context) (net.PacketConn, *quic.Conn, error)

// L4Client implements Cloudflare WARP's private HTTP/3 TCP CONNECT service.
// It isn't a CONNECT-IP or MASQUE protocol and is kept in this product-specific
// package solely to preserve the legacy WARP h3-l4proxy mode.
type L4Client struct {
	dialFn  DialQUICFunc
	runLock *semaphore.Weighted
	runCtx  context.Context

	clientConn *http3.ClientConn
	quicConn   *quic.Conn
	packetConn net.PacketConn
}

func NewL4Client(runCtx context.Context, dialFn DialQUICFunc) *L4Client {
	return &L4Client{dialFn: dialFn, runLock: semaphore.NewWeighted(1), runCtx: runCtx}
}

func (c *L4Client) Close() error {
	return c.closeConn(nil)
}

func (c *L4Client) closeConn(expected *http3.ClientConn) error {
	_ = c.runLock.Acquire(context.Background(), 1)
	clientConn := c.clientConn
	quicConn := c.quicConn
	packetConn := c.packetConn
	if expected != nil && clientConn != expected {
		c.runLock.Release(1)
		return nil
	}
	c.clientConn = nil
	c.quicConn = nil
	c.packetConn = nil
	c.runLock.Release(1)

	var closeErr error
	if clientConn != nil {
		closeErr = clientConn.CloseWithError(0, "client closed")
	} else if quicConn != nil {
		closeErr = quicConn.CloseWithError(0, "client closed")
	}
	if packetConn != nil {
		if err := packetConn.Close(); closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}

func (c *L4Client) dialConn(ctx context.Context) (*http3.ClientConn, *quic.Conn, error) {
	if err := c.runLock.Acquire(ctx, 1); err != nil {
		return nil, nil, err
	}
	defer c.runLock.Release(1)
	if c.clientConn != nil {
		return c.clientConn, c.quicConn, nil
	}
	if err := c.runCtx.Err(); err != nil {
		return nil, nil, err
	}

	dialCtx, cancel := context.WithCancel(ctx)
	stop := contextutils.AfterFunc(c.runCtx, cancel)
	defer func() {
		stop()
		cancel()
	}()
	packetConn, quicConn, err := c.dialFn(dialCtx)
	if err != nil {
		return nil, nil, err
	}
	transport := &http3.Transport{DisableCompression: true}
	clientConn := transport.NewClientConn(quicConn)
	c.clientConn = clientConn
	c.quicConn = quicConn
	c.packetConn = packetConn
	return clientConn, quicConn, nil
}

func (c *L4Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("warp: L4 proxy doesn't support network %q", network)
	}
	clientConn, quicConn, err := c.dialConn(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := clientConn.OpenRequestStream(ctx)
	if err != nil {
		_ = c.closeConn(clientConn)
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+address, nil)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	req.Host = address
	if err := stream.SendRequestHeader(req); err != nil {
		_ = stream.Close()
		_ = c.closeConn(clientConn)
		return nil, err
	}
	response, err := stream.ReadResponse()
	if err != nil {
		_ = stream.Close()
		_ = c.closeConn(clientConn)
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		_ = stream.Close()
		return nil, fmt.Errorf("warp: L4 CONNECT rejected with %s", response.Status)
	}
	if quicConn == nil {
		_ = stream.Close()
		_ = c.closeConn(clientConn)
		return nil, errors.New("warp: L4 proxy has no QUIC connection")
	}
	return &l4StreamConn{
		RequestStream: stream,
		localAddr:     quicConn.LocalAddr(),
		remoteAddr:    quicConn.RemoteAddr(),
	}, nil
}

type l4StreamConn struct {
	*http3.RequestStream
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *l4StreamConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *l4StreamConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *l4StreamConn) Close() error {
	c.RequestStream.CancelRead(0)
	return c.RequestStream.Close()
}
