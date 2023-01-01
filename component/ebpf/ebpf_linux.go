//go:build !android

package ebpf

import (
	"fmt"
	"net/netip"

	"github.com/Dreamacro/clash/common/cmd"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/ebpf/redir"
	"github.com/Dreamacro/clash/component/ebpf/tc"
	C "github.com/Dreamacro/clash/constant"
	"github.com/sagernet/netlink"
)

func GetAutoDetectInterface() (string, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return "", err
	}

	for _, route := range routes {
		if route.Dst == nil {
			lk, err := netlink.LinkByIndex(route.LinkIndex)
			if err != nil {
				return "", err
			}

			if lk.Type() == "tuntap" {
				continue
			}

			return lk.Attrs().Name, nil
		}
	}

	return "", fmt.Errorf("interface not found")
}

// NewTcEBpfProgram new redirect to tun ebpf program
func NewTcEBpfProgram(ifaceNames []string, tunName string) (*TcEBpfProgram, error) {
	tunIface, err := netlink.LinkByName(tunName)
	if err != nil {
		return nil, fmt.Errorf("lookup network iface %q: %w", tunName, err)
	}

	tunIndex := uint32(tunIface.Attrs().Index)

	dialer.DefaultRoutingMark.Store(C.ClashTrafficMark)

	ifMark := uint32(dialer.DefaultRoutingMark.Load())

	var pros []C.EBpf
	for _, ifaceName := range ifaceNames {
		iface, err := netlink.LinkByName(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("lookup network iface %q: %w", ifaceName, err)
		}
		if iface.Attrs().OperState != netlink.OperUp {
			return nil, fmt.Errorf("network iface %q is down", ifaceName)
		}

		attrs := iface.Attrs()
		index := attrs.Index

		tcPro := tc.NewEBpfTc(ifaceName, index, ifMark, tunIndex)
		if err = tcPro.Start(); err != nil {
			return nil, err
		}

		pros = append(pros, tcPro)
	}

	systemSetting(ifaceNames...)

	return &TcEBpfProgram{pros: pros, rawNICs: ifaceNames}, nil
}

// NewRedirEBpfProgram new auto redirect ebpf program
func NewRedirEBpfProgram(ifaceNames []string, redirPort uint16, defaultRouteInterfaceName string) (*TcEBpfProgram, error) {
	defaultRouteInterface, err := netlink.LinkByName(defaultRouteInterfaceName)
	if err != nil {
		return nil, fmt.Errorf("lookup network iface %q: %w", defaultRouteInterfaceName, err)
	}

	defaultRouteIndex := uint32(defaultRouteInterface.Attrs().Index)

	var pros []C.EBpf
	for _, ifaceName := range ifaceNames {
		iface, err := netlink.LinkByName(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("lookup network iface %q: %w", ifaceName, err)
		}

		attrs := iface.Attrs()
		index := attrs.Index

		addrs, err := netlink.AddrList(iface, netlink.FAMILY_V4)
		if err != nil {
			return nil, fmt.Errorf("lookup network iface %q address: %w", ifaceName, err)
		}

		if len(addrs) == 0 {
			return nil, fmt.Errorf("network iface %q does not contain any ipv4 addresses", ifaceName)
		}

		address, _ := netip.AddrFromSlice(addrs[0].IP)
		redirAddrPort := netip.AddrPortFrom(address, redirPort)

		redirPro := redir.NewEBpfRedirect(ifaceName, index, 0, defaultRouteIndex, redirAddrPort)
		if err = redirPro.Start(); err != nil {
			return nil, err
		}

		pros = append(pros, redirPro)
	}

	systemSetting(ifaceNames...)

	return &TcEBpfProgram{pros: pros, rawNICs: ifaceNames}, nil
}

func systemSetting(ifaceNames ...string) {
	_, _ = cmd.ExecCmd("sysctl -w net.ipv4.ip_forward=1")
	_, _ = cmd.ExecCmd("sysctl -w net.ipv4.conf.all.forwarding=1")
	_, _ = cmd.ExecCmd("sysctl -w net.ipv4.conf.all.accept_local=1")
	_, _ = cmd.ExecCmd("sysctl -w net.ipv4.conf.all.accept_redirects=1")
	_, _ = cmd.ExecCmd("sysctl -w net.ipv4.conf.all.rp_filter=0")

	for _, ifaceName := range ifaceNames {
		_, _ = cmd.ExecCmd(fmt.Sprintf("sysctl -w net.ipv4.conf.%s.forwarding=1", ifaceName))
		_, _ = cmd.ExecCmd(fmt.Sprintf("sysctl -w net.ipv4.conf.%s.accept_local=1", ifaceName))
		_, _ = cmd.ExecCmd(fmt.Sprintf("sysctl -w net.ipv4.conf.%s.accept_redirects=1", ifaceName))
		_, _ = cmd.ExecCmd(fmt.Sprintf("sysctl -w net.ipv4.conf.%s.rp_filter=0", ifaceName))
	}
}
