package commons

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/Dreamacro/clash/listener/tun/device"
	"github.com/Dreamacro/clash/listener/tun/device/tun"
	"github.com/Dreamacro/clash/log"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func GetAutoDetectInterface() (string, error) {
	ifname, err := getAutoDetectInterfaceByFamily(winipcfg.AddressFamily(windows.AF_INET))
	if err == nil {
		return ifname, err
	}

	return getAutoDetectInterfaceByFamily(winipcfg.AddressFamily(windows.AF_INET6))
}

func ConfigInterfaceAddress(dev device.Device, addr *net.IPNet, forceMTU int, autoRoute bool) error {
	retryOnFailure := StartedAtBoot()
	tryTimes := 0
startOver:
	var err error
	if tryTimes > 0 {
		log.Infoln("Retrying interface configuration after failure because system just booted (T+%v): %v", windows.DurationSinceBoot(), err)
		time.Sleep(time.Second)
		retryOnFailure = retryOnFailure && tryTimes < 15
	}
	tryTimes++

	luid := winipcfg.LUID(dev.(*tun.TUN).LUID())

	if guid, err1 := luid.GUID(); err1 == nil {
		log.Infoln("[wintun]: tun adapter GUID: %s", guid.String())
	}

	tunAddress := ParseIPCidr(addr.String())
	addresses := []net.IPNet{tunAddress.IPNet()}

	family := winipcfg.AddressFamily(windows.AF_INET)
	familyV6 := winipcfg.AddressFamily(windows.AF_INET6)

	currentFamily := winipcfg.AddressFamily(windows.AF_INET6)
	if addr.IP.To4() != nil {
		currentFamily = winipcfg.AddressFamily(windows.AF_INET)
	}

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

	if autoRoute {
		allowedIPs := []*IPCidr{}
		routeArr := append(ROUTES, "224.0.0.0/4", "255.255.255.255/32")

		for _, route := range routeArr {
			allowedIPs = append(allowedIPs, ParseIPCidr(route))
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

	err = luid.SetIPAddressesForFamily(currentFamily, addresses)
	if err == windows.ERROR_OBJECT_ALREADY_EXISTS {
		cleanupAddressesOnDisconnectedInterfaces(currentFamily, addresses)
		err = luid.SetIPAddressesForFamily(currentFamily, addresses)
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
	if forceMTU > 0 {
		ipif.NLMTU = uint32(forceMTU)
	}
	if foundDefault4 {
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
	if forceMTU > 0 {
		ipif6.NLMTU = uint32(forceMTU)
	}
	if foundDefault6 {
		ipif6.UseAutomaticMetric = false
		ipif6.Metric = 0
	}
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
