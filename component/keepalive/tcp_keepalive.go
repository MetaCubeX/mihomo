package keepalive

import (
	"net"
	"runtime"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/utils"
)

var (
	keepAliveIdle     = atomic.NewInt64(0)
	keepAliveInterval = atomic.NewInt64(0)
	disableKeepAlive  = atomic.NewBool(false)

	SetDisableKeepAliveCallback = utils.NewCallback[bool]()
)

func SetKeepAliveIdle(t time.Duration) {
	keepAliveIdle.Store(int64(t))
}

func SetKeepAliveInterval(t time.Duration) {
	keepAliveInterval.Store(int64(t))
}

func KeepAliveIdle() time.Duration {
	return time.Duration(keepAliveIdle.Load())
}

func KeepAliveInterval() time.Duration {
	return time.Duration(keepAliveInterval.Load())
}

func SetDisableKeepAlive(disable bool) {
	if runtime.GOOS == "android" {
		setDisableKeepAlive(true)
	} else {
		setDisableKeepAlive(disable)
	}
}

func setDisableKeepAlive(disable bool) {
	disableKeepAlive.Store(disable)
	SetDisableKeepAliveCallback.Emit(disable)
}

func DisableKeepAlive() bool {
	return disableKeepAlive.Load()
}

func SetNetDialer(dialer *net.Dialer) {
	setNetDialer(dialer)
}

func SetNetListenConfig(lc *net.ListenConfig) {
	setNetListenConfig(lc)
}

func TCPKeepAlive(c net.Conn) {
	if tcp, ok := c.(TCPConn); ok && tcp != nil {
		tcpKeepAlive(tcp)
	}
}
