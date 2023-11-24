package vmess

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/common/buf"
	"github.com/metacubex/mihomo/common/net"
)

type httpUpgradeEarlyConn struct {
	*net.BufferedConn
	create sync.Once
	done   bool
	err    error
}

func (c *httpUpgradeEarlyConn) readResponse() {
	var request http.Request
	response, err := http.ReadResponse(c.Reader(), &request)
	c.done = true
	if err != nil {
		c.err = err
		return
	}
	if response.StatusCode != http.StatusSwitchingProtocols ||
		!strings.EqualFold(response.Header.Get("Connection"), "upgrade") ||
		!strings.EqualFold(response.Header.Get("Upgrade"), "websocket") {
		c.err = fmt.Errorf("unexpected status: %s", response.Status)
		return
	}
}

func (c *httpUpgradeEarlyConn) Read(p []byte) (int, error) {
	c.create.Do(c.readResponse)
	if c.err != nil {
		return 0, c.err
	}
	return c.BufferedConn.Read(p)
}

func (c *httpUpgradeEarlyConn) ReadBuffer(buffer *buf.Buffer) error {
	c.create.Do(c.readResponse)
	if c.err != nil {
		return c.err
	}
	return c.BufferedConn.ReadBuffer(buffer)
}

func (c *httpUpgradeEarlyConn) ReaderReplaceable() bool {
	return c.done
}

func (c *httpUpgradeEarlyConn) ReaderPossiblyReplaceable() bool {
	return !c.done
}

func (c *httpUpgradeEarlyConn) ReadCached() *buf.Buffer {
	if c.done {
		return c.BufferedConn.ReadCached()
	}
	return nil
}
