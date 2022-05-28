package commons

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	C "github.com/Dreamacro/clash/constant"
)

var (
	defaultRoutes = []string{"1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5", "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1"}

	monitorDuration = 10 * time.Second
	monitorStarted  = false
	monitorStop     = make(chan struct{}, 2)
	monitorMux      sync.Mutex

	tunStatus            = C.TunDisabled
	tunChangeCallback    C.TUNChangeCallback
	errInterfaceNotFound = errors.New("default interface not found")
)

func ipv4MaskString(bits int) string {
	m := net.CIDRMask(bits, 32)
	if len(m) != 4 {
		panic("ipv4Mask: len must be 4 bytes")
	}

	return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
}

func SetTunChangeCallback(callback C.TUNChangeCallback) {
	tunChangeCallback = callback
}
