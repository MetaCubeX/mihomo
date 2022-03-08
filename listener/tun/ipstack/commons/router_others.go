//go:build !darwin && !linux && !windows

package commons

import (
	"fmt"
	"net"
	"runtime"

	"github.com/Dreamacro/clash/listener/tun/device"
)

func GetAutoDetectInterface() (string, error) {
	return "", fmt.Errorf("can not auto detect interface-name on this OS: %s, you must be detecting interface-name by manual", runtime.GOOS)
}

func ConfigInterfaceAddress(dev device.Device, addr *net.IPNet, forceMTU int, autoRoute bool) error {
	return fmt.Errorf("unsupported on this OS: %s", runtime.GOOS)
}
