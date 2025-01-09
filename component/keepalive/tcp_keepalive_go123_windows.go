//go:build go1.23 && windows

// copy and modify from golang1.23's internal/syscall/windows/version_windows.go

package keepalive

import (
	"errors"
	"sync"
	"syscall"

	"github.com/metacubex/mihomo/constant/features"

	"golang.org/x/sys/windows"
)

var (
	supportTCPKeepAliveIdle     bool
	supportTCPKeepAliveInterval bool
	supportTCPKeepAliveCount    bool
)

var initTCPKeepAlive = sync.OnceFunc(func() {
	s, err := windows.WSASocket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP, nil, 0, windows.WSA_FLAG_NO_HANDLE_INHERIT)
	if err != nil {
		// Fallback to checking the Windows version.
		major, build := features.WindowsMajorVersion, features.WindowsBuildNumber
		supportTCPKeepAliveIdle = major >= 10 && build >= 16299
		supportTCPKeepAliveInterval = major >= 10 && build >= 16299
		supportTCPKeepAliveCount = major >= 10 && build >= 15063
		return
	}
	defer windows.Closesocket(s)
	var optSupported = func(opt int) bool {
		err := windows.SetsockoptInt(s, syscall.IPPROTO_TCP, opt, 1)
		return !errors.Is(err, syscall.WSAENOPROTOOPT)
	}
	supportTCPKeepAliveIdle = optSupported(windows.TCP_KEEPIDLE)
	supportTCPKeepAliveInterval = optSupported(windows.TCP_KEEPINTVL)
	supportTCPKeepAliveCount = optSupported(windows.TCP_KEEPCNT)
})

// SupportTCPKeepAliveIdle indicates whether TCP_KEEPIDLE is supported.
// The minimal requirement is Windows 10.0.16299.
func SupportTCPKeepAliveIdle() bool {
	initTCPKeepAlive()
	return supportTCPKeepAliveIdle
}

// SupportTCPKeepAliveInterval indicates whether TCP_KEEPINTVL is supported.
// The minimal requirement is Windows 10.0.16299.
func SupportTCPKeepAliveInterval() bool {
	initTCPKeepAlive()
	return supportTCPKeepAliveInterval
}

// SupportTCPKeepAliveCount indicates whether TCP_KEEPCNT is supported.
// supports TCP_KEEPCNT.
// The minimal requirement is Windows 10.0.15063.
func SupportTCPKeepAliveCount() bool {
	initTCPKeepAlive()
	return supportTCPKeepAliveCount
}
