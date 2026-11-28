package tunnel

import (
	"sync/atomic"
	"time"
)

type tcpHalfCloseTimeout struct {
	client time.Duration
	server time.Duration
}

var halfCloseTimeout atomic.Pointer[tcpHalfCloseTimeout]

// SetTCPHalfCloseTimeout applies to new relays; existing relays keep their snapshot.
func SetTCPHalfCloseTimeout(client, server time.Duration) {
	halfCloseTimeout.Store(&tcpHalfCloseTimeout{client: client, server: server})
}

// TCPHalfCloseTimeout returns the idle allowances after client and server EOF.
func TCPHalfCloseTimeout() (client, server time.Duration) {
	if timeout := halfCloseTimeout.Load(); timeout != nil {
		return timeout.client, timeout.server
	}
	return 0, 0
}
