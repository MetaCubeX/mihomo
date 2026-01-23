package inner

import (
	"errors"
	"net"
	"sync"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
)

var tunnel C.Tunnel

func New(t C.Tunnel) {
	tunnel = t
}

func GetTunnel() C.Tunnel {
	return tunnel
}

type errConn struct {
	net.Conn
	errOnce sync.Once
	errMu   sync.RWMutex
	err     error
}

func newErrConn(conn net.Conn, errCh <-chan error) net.Conn {
	c := &errConn{Conn: conn}
	go func() {
		if err, ok := <-errCh; ok && err != nil {
			c.setErr(err)
			_ = c.Conn.Close()
		}
	}()
	return c
}

func (c *errConn) setErr(err error) {
	if err == nil {
		return
	}
	c.errOnce.Do(func() {
		c.errMu.Lock()
		c.err = err
		c.errMu.Unlock()
	})
}

func (c *errConn) getErr() error {
	c.errMu.RLock()
	defer c.errMu.RUnlock()
	return c.err
}

func (c *errConn) Read(b []byte) (int, error) {
	if err := c.getErr(); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(b)
	if err != nil {
		if err2 := c.getErr(); err2 != nil {
			return n, err2
		}
	}
	return n, err
}

func (c *errConn) Write(b []byte) (int, error) {
	if err := c.getErr(); err != nil {
		return 0, err
	}
	n, err := c.Conn.Write(b)
	if err2 := c.getErr(); err2 != nil {
		return n, err2
	}
	return n, err
}

func HandleTcp(tunnel C.Tunnel, address string, proxy string, withAccurateError bool) (conn net.Conn, err error) {
	if tunnel == nil {
		return nil, errors.New("tunnel uninitialized")
	}
	// executor Parsed
	conn1, conn2 := N.Pipe()

	metadata := &C.Metadata{}
	metadata.NetWork = C.TCP
	metadata.Type = C.INNER
	metadata.DNSMode = C.DNSNormal
	metadata.Process = C.MihomoName
	if proxy != "" {
		metadata.SpecialProxy = proxy
	}
	if err = metadata.SetRemoteAddress(address); err != nil {
		return nil, err
	}

	if withAccurateError {
		errCh := make(chan error, 1)
		go func() {
			errCh <- tunnel.HandleTCPConnWithError(conn2, metadata)
			close(errCh)
		}()
		return newErrConn(conn1, errCh), nil
	}

	go tunnel.HandleTCPConn(conn2, metadata)
	return conn1, nil
}
