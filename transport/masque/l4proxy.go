package masque

import (
	"context"
	"fmt"
	"net"
	"unsafe"

	"github.com/metacubex/mihomo/common/contextutils"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"golang.org/x/sync/semaphore"
)

const (
	L4ConnectSNI = "consumer-masque-proxy.cloudflareclient.com"
)

type DialQuicFn func(ctx context.Context) (net.PacketConn, *quic.Conn, error)

type L4Client struct {
	dialFn     DialQuicFn
	runLock    *semaphore.Weighted
	runCtx     context.Context
	clientConn *http3.ClientConn
}

func NewL4Client(runCtx context.Context, dialFn DialQuicFn) *L4Client {
	return &L4Client{
		dialFn:  dialFn,
		runLock: semaphore.NewWeighted(1),
		runCtx:  runCtx,
	}
}

// Close closes the client.
// The caller should cancel runCtx before calling Close
func (c *L4Client) Close() error {
	return c.closeConn(nil)
}

func (c *L4Client) closeConn(clientConn *http3.ClientConn) error {
	_ = c.runLock.Acquire(context.Background(), 1) // background context never returns error
	if clientConn == nil {
		clientConn = c.clientConn
	}
	if c.clientConn == clientConn {
		c.clientConn = nil
	}
	c.runLock.Release(1)

	if clientConn != nil {
		return clientConn.CloseWithError(0, "client closed")
	}
	return nil
}

func (c *L4Client) dialConn(ctx context.Context) (*http3.ClientConn, error) {
	err := c.runLock.Acquire(ctx, 1)
	if err != nil {
		return nil, err
	}
	defer c.runLock.Release(1)
	if c.clientConn != nil {
		return c.clientConn, nil
	}

	if err = c.runCtx.Err(); err != nil {
		return nil, err
	}

	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := contextutils.AfterFunc(c.runCtx, cancel)
	defer stop()

	_, quicConn, err := c.dialFn(dialCtx)
	if err != nil {
		return nil, err
	}
	tr := &http3.Transport{}
	clientConn := tr.NewClientConn(quicConn)
	c.clientConn = clientConn
	return clientConn, nil
}

func (c *L4Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	clientConn, err := c.dialConn(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := clientConn.OpenRequestStream(ctx)
	if err != nil {
		_ = c.closeConn(clientConn) // close underlay connection if we failed to open a stream
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+address, nil)
	if err != nil {
		return nil, err
	}
	req.Host = address
	if err = stream.SendRequestHeader(req); err != nil {
		return nil, err
	}
	response, err := stream.ReadResponse()
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Errorf("CONNECT rejected with status %d", response.StatusCode)
	}
	return &l4StreamConn{stream, clientConn}, nil
}

type l4StreamConn struct {
	*http3.RequestStream
	clientConn *http3.ClientConn
}

func (c *l4StreamConn) quicConn() *quic.Conn {
	return *(**quic.Conn)(unsafe.Pointer(c.clientConn)) // the first field of the http3.ClientConn is a *quic.Conn
}

func (c *l4StreamConn) LocalAddr() net.Addr {
	return c.quicConn().LocalAddr()
}

func (c *l4StreamConn) RemoteAddr() net.Addr {
	return c.quicConn().RemoteAddr()
}

func (c *l4StreamConn) Close() error {
	c.RequestStream.CancelRead(0)
	return c.RequestStream.Close()
}
