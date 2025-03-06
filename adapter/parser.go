package adapter

import (
	"fmt"
	"net"
	"net/netip"

	tlsC "github.com/metacubex/mihomo/component/tls"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
)

func ParseProxy(mapping map[string]any) (C.Proxy, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	proxyType, existType := mapping["type"].(string)
	if !existType {
		return nil, fmt.Errorf("missing type")
	}

	if interfaceName, ok := mapping["interface-name"].(string); ok && interfaceName == "auto" {
		mapping["interface-name"] = ""
		addr, _ := mapping["server"].(string)
		if ip := net.ParseIP(addr); ip != nil {
			iface, err := findInterfaceByAddr(ip)
			if err == nil && iface != nil {
				mapping["interface-name"] = iface.Name
			}
		}
	}

	var (
		proxy C.ProxyAdapter
		err   error
	)
	switch proxyType {
	case "ss":
		ssOption := &outbound.ShadowSocksOption{ClientFingerprint: tlsC.GetGlobalFingerprint()}
		err = decoder.Decode(mapping, ssOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewShadowSocks(*ssOption)
	case "ssr":
		ssrOption := &outbound.ShadowSocksROption{}
		err = decoder.Decode(mapping, ssrOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewShadowSocksR(*ssrOption)
	case "socks5":
		socksOption := &outbound.Socks5Option{}
		err = decoder.Decode(mapping, socksOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewSocks5(*socksOption)
	case "http":
		httpOption := &outbound.HttpOption{}
		err = decoder.Decode(mapping, httpOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewHttp(*httpOption)
	case "vmess":
		vmessOption := &outbound.VmessOption{
			HTTPOpts: outbound.HTTPOptions{
				Method: "GET",
				Path:   []string{"/"},
			},
			ClientFingerprint: tlsC.GetGlobalFingerprint(),
		}

		err = decoder.Decode(mapping, vmessOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewVmess(*vmessOption)
	case "vless":
		vlessOption := &outbound.VlessOption{ClientFingerprint: tlsC.GetGlobalFingerprint()}
		err = decoder.Decode(mapping, vlessOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewVless(*vlessOption)
	case "snell":
		snellOption := &outbound.SnellOption{}
		err = decoder.Decode(mapping, snellOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewSnell(*snellOption)
	case "trojan":
		trojanOption := &outbound.TrojanOption{ClientFingerprint: tlsC.GetGlobalFingerprint()}
		err = decoder.Decode(mapping, trojanOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewTrojan(*trojanOption)
	case "hysteria":
		hyOption := &outbound.HysteriaOption{}
		err = decoder.Decode(mapping, hyOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewHysteria(*hyOption)
	case "hysteria2":
		hyOption := &outbound.Hysteria2Option{}
		err = decoder.Decode(mapping, hyOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewHysteria2(*hyOption)
	case "wireguard":
		wgOption := &outbound.WireGuardOption{}
		err = decoder.Decode(mapping, wgOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewWireGuard(*wgOption)
	case "tuic":
		tuicOption := &outbound.TuicOption{}
		err = decoder.Decode(mapping, tuicOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewTuic(*tuicOption)
	case "direct":
		directOption := &outbound.DirectOption{}
		err = decoder.Decode(mapping, directOption)
		if err != nil {
			break
		}
		proxy = outbound.NewDirectWithOption(*directOption)
	case "dns":
		dnsOptions := &outbound.DnsOption{}
		err = decoder.Decode(mapping, dnsOptions)
		if err != nil {
			break
		}
		proxy = outbound.NewDnsWithOption(*dnsOptions)
	case "reject":
		rejectOption := &outbound.RejectOption{}
		err = decoder.Decode(mapping, rejectOption)
		if err != nil {
			break
		}
		proxy = outbound.NewRejectWithOption(*rejectOption)
	case "ssh":
		sshOption := &outbound.SshOption{}
		err = decoder.Decode(mapping, sshOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewSsh(*sshOption)
	case "mieru":
		mieruOption := &outbound.MieruOption{}
		err = decoder.Decode(mapping, mieruOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewMieru(*mieruOption)
	case "anytls":
		anytlsOption := &outbound.AnyTLSOption{}
		err = decoder.Decode(mapping, anytlsOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewAnyTLS(*anytlsOption)
	default:
		return nil, fmt.Errorf("unsupport proxy type: %s", proxyType)
	}

	if err != nil {
		return nil, err
	}

	if muxMapping, muxExist := mapping["smux"].(map[string]any); muxExist {
		muxOption := &outbound.SingMuxOption{}
		err = decoder.Decode(muxMapping, muxOption)
		if err != nil {
			return nil, err
		}
		if muxOption.Enabled {
			proxy, err = outbound.NewSingMux(*muxOption, proxy, proxy.(outbound.ProxyBase))
			if err != nil {
				return nil, err
			}
		}
	}

	return NewProxy(proxy), nil
}

func findInterfaceByAddr(ipAddr net.IP) (*net.Interface, error) {
	if ipAddr == nil {
		return nil, fmt.Errorf("nil IP address")
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %w", err)
	}

	var addr netip.Addr
	if ipv4 := ipAddr.To4(); ipv4 != nil {
		addr, _ = netip.AddrFromSlice(ipv4)
	} else {
		addr, _ = netip.AddrFromSlice(ipAddr)
	}

	var bestMatch *net.Interface
	var bestPrefixLen int = -1
	var bestMatchDistance uint64 = 1<<64 - 1 // Max uint64 value

	for i, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, a := range addrs {
			cidrStr := a.String()
			prefix, err := netip.ParsePrefix(cidrStr)
			if err != nil {
				continue
			}

			if prefix.Contains(addr) {
				prefixLen := prefix.Bits()

				networkAddr := prefix.Addr()
				distance := ipDistance(networkAddr, addr)

				// Choose interface with:
				// 1. Longer prefix (more specific network), or
				// 2. Same prefix length but closer network address
				if prefixLen > bestPrefixLen ||
					(prefixLen == bestPrefixLen && distance < bestMatchDistance) {
					bestPrefixLen = prefixLen
					bestMatchDistance = distance
					bestMatch = &interfaces[i]
				}
			}
		}
	}

	if bestMatch != nil {
		return bestMatch, nil
	}

	return nil, fmt.Errorf("no interface found with address %s", ipAddr)
}

func ipDistance(a, b netip.Addr) uint64 {
	aBytes := a.AsSlice()
	bBytes := b.AsSlice()

	minLen := len(aBytes)
	if len(bBytes) < minLen {
		minLen = len(bBytes)
	}

	var distance uint64
	for i := 0; i < minLen; i++ {
		// Add the absolute difference between bytes
		if aBytes[i] > bBytes[i] {
			distance = (distance << 8) + uint64(aBytes[i]-bBytes[i])
		} else {
			distance = (distance << 8) + uint64(bBytes[i]-aBytes[i])
		}
	}

	return distance
}
