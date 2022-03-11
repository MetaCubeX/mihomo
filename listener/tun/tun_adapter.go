package tun

import (
	"fmt"
	"net/netip"
	"net/url"
	"runtime"
	"strings"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/cmd"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/tun/device"
	"github.com/Dreamacro/clash/listener/tun/device/fdbased"
	"github.com/Dreamacro/clash/listener/tun/device/tun"
	"github.com/Dreamacro/clash/listener/tun/ipstack"
	"github.com/Dreamacro/clash/listener/tun/ipstack/commons"
	"github.com/Dreamacro/clash/listener/tun/ipstack/gvisor"
	"github.com/Dreamacro/clash/listener/tun/ipstack/system"
	"github.com/Dreamacro/clash/log"
)

// New TunAdapter
func New(tunConf *config.Tun, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) (ipstack.Stack, error) {
	devName := tunConf.Device
	if devName == "" {
		devName = generateDeviceName()
	}

	tunAddress := netip.MustParsePrefix("198.18.0.1/16")
	autoRoute := tunConf.AutoRoute
	stackType := tunConf.Stack
	mtu := 9000

	var tunDevice device.Device
	var tunStack ipstack.Stack

	var err error

	// new tun device
	tunDevice, err = parseDevice(devName, uint32(mtu))
	if err != nil {
		return nil, fmt.Errorf("can't open tun: %w", err)
	}

	// new ip stack
	switch stackType {
	case C.TunGvisor:
		err = tunDevice.UseEndpoint()
		if err != nil {
			_ = tunDevice.Close()
			return nil, fmt.Errorf("can't attach endpoint to tun: %w", err)
		}

		tunStack, err = gvisor.New(tunDevice,
			&gvisor.GVHandler{
				DNSAdds: tunConf.DNSHijack,
				TCPIn:   tcpIn, UDPIn: udpIn,
			},
			gvisor.WithDefault())

		if err != nil {
			_ = tunDevice.Close()
			return nil, fmt.Errorf("can't New gvisor stack: %w", err)
		}
	case C.TunSystem:
		err = tunDevice.UseIOBased()
		if err != nil {
			_ = tunDevice.Close()
			return nil, fmt.Errorf("can't attach endpoint to tun: %w", err)
		}

		tunStack, err = system.New(tunDevice, tunConf.DNSHijack, tunAddress, tcpIn, udpIn)
		if err != nil {
			_ = tunDevice.Close()
			return nil, fmt.Errorf("can't New system stack: %w", err)
		}
	default:
		// ignore it, should never happen
	}

	// setting address and routing
	err = commons.ConfigInterfaceAddress(tunDevice, tunAddress, mtu, autoRoute)
	if err != nil {
		_ = tunDevice.Close()
		return nil, fmt.Errorf("setting interface address and routing failed: %w", err)
	}

	setAtLatest(stackType)

	log.Infoln("TUN stack listening at: %s(%s), mtu: %d, auto route: %v, ip stack: %s", tunDevice.Name(), tunAddress.Addr().String(), mtu, autoRoute, stackType)
	return tunStack, nil
}

func generateDeviceName() string {
	switch runtime.GOOS {
	case "darwin":
		return tun.Driver + "://utun"
	case "windows":
		return tun.Driver + "://Clash"
	default:
		return tun.Driver + "://clash0"
	}
}

func parseDevice(s string, mtu uint32) (device.Device, error) {
	if !strings.Contains(s, "://") {
		s = fmt.Sprintf("%s://%s", tun.Driver /* default driver */, s)
	}

	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	name := u.Host
	driver := strings.ToLower(u.Scheme)

	switch driver {
	case fdbased.Driver:
		return fdbased.Open(name, mtu)
	case tun.Driver:
		return tun.Open(name, mtu)
	default:
		return nil, fmt.Errorf("unsupported driver: %s", driver)
	}
}

func setAtLatest(stackType C.TUNStack) {
	if stackType != C.TunSystem {
		return
	}

	switch runtime.GOOS {
	case "windows":
		_, _ = cmd.ExecCmd("ipconfig /renew")
	case "linux":
		// _, _ = cmd.ExecCmd("sysctl -w net.ipv4.ip_forward=1")
		// _, _ = cmd.ExecCmd("iptables -t filter -P FORWARD ACCEPT")
	}
}
