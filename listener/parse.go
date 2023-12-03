package listener

import (
	"fmt"

	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	IN "github.com/metacubex/mihomo/listener/inbound"
)

func ParseListener(mapping map[string]any) (C.InboundListener, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "inbound", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	proxyType, existType := mapping["type"].(string)
	if !existType {
		return nil, fmt.Errorf("missing type")
	}

	var (
		listener C.InboundListener
		err      error
	)
	switch proxyType {
	case "socks":
		socksOption := &IN.SocksOption{UDP: true}
		err = decoder.Decode(mapping, socksOption)
		if err != nil {
			return nil, err
		}
		listener, err = IN.NewSocks(socksOption)
	case "http":
		httpOption := &IN.HTTPOption{}
		err = decoder.Decode(mapping, httpOption)
		if err != nil {
			return nil, err
		}
		listener, err = IN.NewHTTP(httpOption)
	case "tproxy":
		tproxyOption := &IN.TProxyOption{UDP: true}
		err = decoder.Decode(mapping, tproxyOption)
		if err != nil {
			return nil, err
		}
		listener, err = IN.NewTProxy(tproxyOption)
	case "redir":
		redirOption := &IN.RedirOption{}
		err = decoder.Decode(mapping, redirOption)
		if err != nil {
			return nil, err
		}
		listener, err = IN.NewRedir(redirOption)
	case "mixed":
		mixedOption := &IN.MixedOption{UDP: true}
		err = decoder.Decode(mapping, mixedOption)
		if err != nil {
			return nil, err
		}
		listener, err = IN.NewMixed(mixedOption)
	case "tunnel":
		tunnelOption := &IN.TunnelOption{}
		err = decoder.Decode(mapping, tunnelOption)
		if err != nil {
			return nil, err
		}
		listener, err = IN.NewTunnel(tunnelOption)
	case "tun":
		tunOption := &IN.TunOption{
			Stack:     C.TunGvisor.String(),
			DNSHijack: []string{"0.0.0.0:53"}, // default hijack all dns query
		}
		err = decoder.Decode(mapping, tunOption)
		if err != nil {
			return nil, err
		}
		listener, err = IN.NewTun(tunOption)
	case "shadowsocks":
		shadowsocksOption := &IN.ShadowSocksOption{UDP: true}
		err = decoder.Decode(mapping, shadowsocksOption)
		if err != nil {
			return nil, err
		}
		listener, err = IN.NewShadowSocks(shadowsocksOption)
	case "vmess":
		vmessOption := &IN.VmessOption{}
		err = decoder.Decode(mapping, vmessOption)
		if err != nil {
			return nil, err
		}
		listener, err = IN.NewVmess(vmessOption)
	case "hysteria2":
		hysteria2Option := &IN.Hysteria2Option{}
		err = decoder.Decode(mapping, hysteria2Option)
		if err != nil {
			return nil, err
		}
		listener, err = IN.NewHysteria2(hysteria2Option)
	case "tuic":
		tuicOption := &IN.TuicOption{
			MaxIdleTime:           15000,
			AuthenticationTimeout: 1000,
			ALPN:                  []string{"h3"},
			MaxUdpRelayPacketSize: 1500,
			CongestionController:  "bbr",
		}
		err = decoder.Decode(mapping, tuicOption)
		if err != nil {
			return nil, err
		}
		listener, err = IN.NewTuic(tuicOption)
	default:
		return nil, fmt.Errorf("unsupport proxy type: %s", proxyType)
	}
	return listener, err
}
