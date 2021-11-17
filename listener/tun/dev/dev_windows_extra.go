//go:build windows
// +build windows

package dev

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Dreamacro/clash/listener/tun/dev/wintun"
	"github.com/Dreamacro/clash/log"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const messageTransportHeaderSize = 0 // size of data preceding content in transport message

type tunWindows struct {
	wt        *wintun.Adapter
	handle    windows.Handle
	close     int32
	running   sync.WaitGroup
	forcedMTU int
	rate      rateJuggler
	session   wintun.Session
	readWait  windows.Handle
	closeOnce sync.Once

	url        string
	name       string
	tunAddress string
	autoRoute  bool
}

// OpenTunDevice return a TunDevice according a URL
func OpenTunDevice(tunAddress string, autoRoute bool) (TunDevice, error) {

	requestedGUID, err := windows.GUIDFromString("{330EAEF8-7578-5DF2-D97B-8DADC0EA85CB}")
	if err == nil {
		WintunStaticRequestedGUID = &requestedGUID
		log.Debugln("Generate GUID: %s", WintunStaticRequestedGUID.String())
	} else {
		log.Warnln("Error parese GUID from string: %v", err)
	}

	interfaceName := "Clash.Mini"
	mtu := 9000

	tun, err := CreateTUN(interfaceName, mtu, tunAddress, autoRoute)
	if err != nil {
		return nil, err
	}

	return tun, nil
}

//
// CreateTUN creates a Wintun interface with the given name. Should a Wintun
// interface with the same name exist, it is reused.
//
func CreateTUN(ifname string, mtu int, tunAddress string, autoRoute bool) (TunDevice, error) {
	return CreateTUNWithRequestedGUID(ifname, WintunStaticRequestedGUID, mtu, tunAddress, autoRoute)
}

//
// CreateTUNWithRequestedGUID creates a Wintun interface with the given name and
// a requested GUID. Should a Wintun interface with the same name exist, it is reused.
//
func CreateTUNWithRequestedGUID(ifname string, requestedGUID *windows.GUID, mtu int, tunAddress string, autoRoute bool) (TunDevice, error) {
	wt, err := wintun.CreateAdapter(ifname, WintunTunnelType, requestedGUID)
	if err != nil {
		return nil, fmt.Errorf("Error creating interface: %w", err)
	}

	forcedMTU := 1420
	if mtu > 0 {
		forcedMTU = mtu
	}

	tun := &tunWindows{
		name:       ifname,
		wt:         wt,
		handle:     windows.InvalidHandle,
		forcedMTU:  forcedMTU,
		tunAddress: tunAddress,
		autoRoute:  autoRoute,
	}

	// config tun ip
	err = tun.configureInterface()
	if err != nil {
		tun.wt.Close()
		return nil, fmt.Errorf("error configure interface: %w", err)
	}

	tun.session, err = wt.StartSession(0x800000) // Ring capacity, 8 MiB
	if err != nil {
		tun.wt.Close()
		return nil, fmt.Errorf("error starting session: %w", err)
	}
	tun.readWait = tun.session.ReadWaitEvent()
	return tun, nil
}

func (tun *tunWindows) Name() string {
	return tun.name
}

func (tun *tunWindows) IsClose() bool {
	return atomic.LoadInt32(&tun.close) == 1
}

func (tun *tunWindows) Read(buff []byte) (int, error) {
	return tun.Read0(buff, messageTransportHeaderSize)
}

func (tun *tunWindows) Write(buff []byte) (int, error) {
	return tun.Write0(buff, messageTransportHeaderSize)
}

func (tun *tunWindows) URL() string {
	return fmt.Sprintf("dev://%s", tun.Name())
}

func (tun *tunWindows) configureInterface() error {
	retryOnFailure := wintun.StartedAtBoot()
	tryTimes := 0
startOver:
	var err error
	if tryTimes > 0 {
		log.Infoln("Retrying interface configuration after failure because system just booted (T+%v): %v", windows.DurationSinceBoot(), err)
		time.Sleep(time.Second)
		retryOnFailure = retryOnFailure && tryTimes < 15
	}
	tryTimes++

	luid := winipcfg.LUID(tun.LUID())
	log.Infoln("[wintun]: tun adapter LUID: %d", luid)
	mtu, err := tun.MTU()

	if err != nil {
		return errors.New("unable to get device mtu")
	}

	family := winipcfg.AddressFamily(windows.AF_INET)
	familyV6 := winipcfg.AddressFamily(windows.AF_INET6)

	tunAddress := wintun.ParseIPCidr(tun.tunAddress + "/16")

	addresses := []net.IPNet{tunAddress.IPNet()}

	err = luid.FlushIPAddresses(familyV6)
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return err
	}
	err = luid.FlushDNS(family)
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return err
	}
	err = luid.FlushDNS(familyV6)
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return err
	}
	err = luid.FlushRoutes(familyV6)
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return err
	}

	foundDefault4 := false
	foundDefault6 := false

	if tun.autoRoute {
		allowedIPs := []*wintun.IPCidr{
			//wintun.ParseIPCidr("0.0.0.0/0"),
			wintun.ParseIPCidr("1.0.0.0/8"),
			wintun.ParseIPCidr("2.0.0.0/7"),
			wintun.ParseIPCidr("4.0.0.0/6"),
			wintun.ParseIPCidr("8.0.0.0/5"),
			wintun.ParseIPCidr("16.0.0.0/4"),
			wintun.ParseIPCidr("32.0.0.0/3"),
			wintun.ParseIPCidr("64.0.0.0/2"),
			wintun.ParseIPCidr("128.0.0.0/1"),
			wintun.ParseIPCidr("224.0.0.0/4"),
			wintun.ParseIPCidr("255.255.255.255/32"),
		}

		estimatedRouteCount := len(allowedIPs)
		routes := make([]winipcfg.RouteData, 0, estimatedRouteCount)
		var haveV4Address, haveV6Address bool = true, false

		for _, allowedip := range allowedIPs {
			allowedip.MaskSelf()
			if (allowedip.Bits() == 32 && !haveV4Address) || (allowedip.Bits() == 128 && !haveV6Address) {
				continue
			}
			route := winipcfg.RouteData{
				Destination: allowedip.IPNet(),
				Metric:      0,
			}
			if allowedip.Bits() == 32 {
				if allowedip.Cidr == 0 {
					foundDefault4 = true
				}
				route.NextHop = net.IPv4zero
			} else if allowedip.Bits() == 128 {
				if allowedip.Cidr == 0 {
					foundDefault6 = true
				}
				route.NextHop = net.IPv6zero
			}
			routes = append(routes, route)
		}

		deduplicatedRoutes := make([]*winipcfg.RouteData, 0, len(routes))
		sort.Slice(routes, func(i, j int) bool {
			if routes[i].Metric != routes[j].Metric {
				return routes[i].Metric < routes[j].Metric
			}
			if c := bytes.Compare(routes[i].NextHop, routes[j].NextHop); c != 0 {
				return c < 0
			}
			if c := bytes.Compare(routes[i].Destination.IP, routes[j].Destination.IP); c != 0 {
				return c < 0
			}
			if c := bytes.Compare(routes[i].Destination.Mask, routes[j].Destination.Mask); c != 0 {
				return c < 0
			}
			return false
		})
		for i := 0; i < len(routes); i++ {
			if i > 0 && routes[i].Metric == routes[i-1].Metric &&
				bytes.Equal(routes[i].NextHop, routes[i-1].NextHop) &&
				bytes.Equal(routes[i].Destination.IP, routes[i-1].Destination.IP) &&
				bytes.Equal(routes[i].Destination.Mask, routes[i-1].Destination.Mask) {
				continue
			}
			deduplicatedRoutes = append(deduplicatedRoutes, &routes[i])
		}

		err = luid.SetRoutesForFamily(family, deduplicatedRoutes)
		if err == windows.ERROR_NOT_FOUND && retryOnFailure {
			goto startOver
		} else if err != nil {
			return fmt.Errorf("unable to set routes: %w", err)
		}
	}

	err = luid.SetIPAddressesForFamily(family, addresses)
	if err == windows.ERROR_OBJECT_ALREADY_EXISTS {
		cleanupAddressesOnDisconnectedInterfaces(family, addresses)
		err = luid.SetIPAddressesForFamily(family, addresses)
	}
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return fmt.Errorf("unable to set ips: %w", err)
	}

	var ipif *winipcfg.MibIPInterfaceRow
	ipif, err = luid.IPInterface(family)
	if err != nil {
		return err
	}
	ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	ipif.DadTransmits = 0
	ipif.ManagedAddressConfigurationSupported = false
	ipif.OtherStatefulConfigurationSupported = false
	if mtu > 0 {
		ipif.NLMTU = uint32(mtu)
	}
	if (family == windows.AF_INET && foundDefault4) || (family == windows.AF_INET6 && foundDefault6) {
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0
	}
	err = ipif.Set()
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return fmt.Errorf("unable to set metric and MTU: %w", err)
	}

	var ipif6 *winipcfg.MibIPInterfaceRow
	ipif6, err = luid.IPInterface(familyV6)
	if err != nil {
		return err
	}
	ipif6.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	ipif6.DadTransmits = 0
	ipif6.ManagedAddressConfigurationSupported = false
	ipif6.OtherStatefulConfigurationSupported = false

	err = ipif6.Set()
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return fmt.Errorf("unable to set v6 metric and MTU: %w", err)
	}

	err = luid.SetDNS(family, []net.IP{net.ParseIP("198.18.0.2")}, nil)
	if err == windows.ERROR_NOT_FOUND && retryOnFailure {
		goto startOver
	} else if err != nil {
		return fmt.Errorf("unable to set DNS %s %s: %w", "198.18.0.2", "nil", err)
	}
	return nil
}

func cleanupAddressesOnDisconnectedInterfaces(family winipcfg.AddressFamily, addresses []net.IPNet) {
	if len(addresses) == 0 {
		return
	}
	addrToStr := func(ip *net.IP) string {
		if ip4 := ip.To4(); ip4 != nil {
			return string(ip4)
		}
		return string(*ip)
	}
	addrHash := make(map[string]bool, len(addresses))
	for i := range addresses {
		addrHash[addrToStr(&addresses[i].IP)] = true
	}
	interfaces, err := winipcfg.GetAdaptersAddresses(family, winipcfg.GAAFlagDefault)
	if err != nil {
		return
	}
	for _, iface := range interfaces {
		if iface.OperStatus == winipcfg.IfOperStatusUp {
			continue
		}
		for address := iface.FirstUnicastAddress; address != nil; address = address.Next {
			ip := address.Address.IP()
			if addrHash[addrToStr(&ip)] {
				ipnet := net.IPNet{IP: ip, Mask: net.CIDRMask(int(address.OnLinkPrefixLength), 8*len(ip))}
				log.Infoln("Cleaning up stale address %s from interface ‘%s’", ipnet.String(), iface.FriendlyName())
				iface.LUID.DeleteIPAddress(ipnet)
			}
		}
	}
}

// GetAutoDetectInterface get ethernet interface
func GetAutoDetectInterface() (string, error) {
	ifname, err := getAutoDetectInterfaceByFamily(winipcfg.AddressFamily(windows.AF_INET))
	if err == nil {
		return ifname, err
	}

	return getAutoDetectInterfaceByFamily(winipcfg.AddressFamily(windows.AF_INET6))
}

func getAutoDetectInterfaceByFamily(family winipcfg.AddressFamily) (string, error) {
	interfaces, err := winipcfg.GetAdaptersAddresses(family, winipcfg.GAAFlagIncludeGateways)
	if err != nil {
		return "", fmt.Errorf("get ethernet interface failure. %w", err)
	}
	for _, iface := range interfaces {
		if iface.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}

		ifname := iface.FriendlyName()
		if ifname == "Clash" {
			continue
		}

		for gatewayAddress := iface.FirstGatewayAddress; gatewayAddress != nil; gatewayAddress = gatewayAddress.Next {
			nextHop := gatewayAddress.Address.IP()

			var ipnet net.IPNet
			if family == windows.AF_INET {
				ipnet = net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
			} else {
				ipnet = net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
			}

			if _, err = iface.LUID.Route(ipnet, nextHop); err == nil {
				return ifname, nil
			}
		}
	}

	return "", errors.New("ethernet interface not found")
}
