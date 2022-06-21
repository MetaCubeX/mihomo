package commons

import (
	"fmt"
	"github.com/Dreamacro/clash/log"
	"net"
	"time"
)

var (
	defaultRoutes = []string{"1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5", "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1"}
)

func ipv4MaskString(bits int) string {
	m := net.CIDRMask(bits, 32)
	if len(m) != 4 {
		panic("ipv4Mask: len must be 4 bytes")
	}

	return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
}

func WaitForTunClose(deviceName string) {
	t := time.NewTicker(600 * time.Millisecond)
	defer t.Stop()
	log.Debugln("[TUN] waiting for device close")
	for {
		<-t.C
		interfaces, err := net.Interfaces()
		if err != nil {
			break
		}

		found := false
		for i := len(interfaces) - 1; i > -1; i-- {
			if interfaces[i].Name == deviceName {
				found = true
				break
			}
		}

		if !found {
			break
		}
	}
}
