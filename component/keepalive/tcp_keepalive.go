package keepalive

import (
	"net"
	"runtime"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/utils"
)

var (
	keepAliveIdle     = atomic.NewTypedValue[time.Duration](0 * time.Second)
	keepAliveInterval = atomic.NewTypedValue[time.Duration](0 * time.Second)
	disableKeepAlive  = atomic.NewBool(false)

	SetDisableKeepAliveCallback = utils.NewCallback[bool]()
)

func SetKeepAliveIdle(t time.Duration) {
	keepAliveIdle.Store(t)
}

func SetKeepAliveInterval(t time.Duration) {
	keepAliveInterval.Store(t)
}

func KeepAliveIdle() time.Duration {
	return keepAliveIdle.Load()
}

func KeepAliveInterval() time.Duration {
	return keepAliveInterval.Load()
}

func SetDisableKeepAlive(disable bool) {
	if runtime.GOOS == "android" {
		setDisableKeepAlive(false)
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
	if tcp, ok := c.(*net.TCPConn); ok && tcp != nil {
		tcpKeepAlive(tcp)
	}
}
