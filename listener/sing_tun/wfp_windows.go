//go:build windows && (amd64 || 386)

package sing_tun

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/windivert"
	"github.com/metacubex/mihomo/listener/sing"

	"github.com/metacubex/sing/common/ranges"
	"golang.org/x/exp/slices"
)

func (l *Listener) startWFP() error {
	options, err := l.wfpOptions()
	if err != nil {
		return err
	}
	device, err := windivert.New(options)
	if err != nil {
		return err
	}
	l.tunIf = device
	if l.options.AutoDetectInterface {
		if err := l.startInterfaceMonitor("WinDivert"); err != nil {
			return err
		}
	}
	if err = device.Start(); err != nil {
		return err
	}
	l.tunName = "WinDivert"
	l.addrStr = fmt.Sprintf("WinDivert(WFP), mtu: %d, ip stack: %s", options.MTU, l.options.Stack)
	resolver.ResetConnection()
	return nil
}

func (l *Listener) wfpOptions() (windivert.Options, error) {
	options := l.options
	if options.GSO || options.FileDescriptor != 0 || options.AutoRedirect || options.StrictRoute ||
		len(options.LoopbackAddress) > 0 || len(options.RouteAddressSet) > 0 || len(options.RouteExcludeAddressSet) > 0 {
		return windivert.Options{}, fmt.Errorf("wfp does not support gso, file-descriptor, auto-redirect, strict-route, loopback-address or route address sets")
	}
	if len(options.IncludeUID)+len(options.IncludeUIDRange)+len(options.ExcludeUID)+len(options.ExcludeUIDRange)+
		len(options.IncludeAndroidUser)+len(options.IncludePackage)+len(options.ExcludePackage)+len(options.IncludeMACAddress)+len(options.ExcludeMACAddress) > 0 {
		return windivert.Options{}, fmt.Errorf("wfp does not support UID, Android user, package or MAC filters")
	}
	mtu := options.MTU
	if mtu == 0 {
		mtu = 1500
	}
	if mtu < 1280 || mtu > 65535 {
		return windivert.Options{}, fmt.Errorf("wfp mtu must be between 1280 and 65535")
	}
	if options.UDPTimeout < 0 || options.UDPTimeout > math.MaxInt64/int64(time.Second) {
		return windivert.Options{}, fmt.Errorf("invalid wfp udp-timeout")
	}
	srcRanges, err := wfpPortRanges(options.ExcludeSrcPortRange)
	if err != nil {
		return windivert.Options{}, fmt.Errorf("exclude-src-port-range: %w", err)
	}
	dstRanges, err := wfpPortRanges(options.ExcludeDstPortRange)
	if err != nil {
		return windivert.Options{}, fmt.Errorf("exclude-dst-port-range: %w", err)
	}
	routes := append(slices.Clone(options.RouteAddress), options.Inet4RouteAddress...)
	excludes := append(slices.Clone(options.RouteExcludeAddress), options.Inet4RouteExcludeAddress...)
	udpTimeout := time.Duration(options.UDPTimeout) * time.Second
	if udpTimeout <= 0 {
		udpTimeout = sing.UDPTimeout
	}
	return windivert.Options{
		Stack: strings.ToLower(options.Stack.String()), Handler: l.handler, UDPTimeout: udpTimeout,
		MTU: mtu, IPv6: len(options.Inet6Address) > 0,
		HijackDNS:        slices.Clone(l.handler.DnsAddrPorts),
		RouteAddress:     append(routes, options.Inet6RouteAddress...),
		ExcludeAddress:   append(excludes, options.Inet6RouteExcludeAddress...),
		IncludeInterface: options.IncludeInterface, ExcludeInterface: options.ExcludeInterface,
		ExcludeSrcPort: options.ExcludeSrcPort, ExcludeDstPort: options.ExcludeDstPort,
		ExcludeSrcPortRange: srcRanges, ExcludeDstPortRange: dstRanges,
	}, nil
}

func wfpPortRanges(values []string) ([]ranges.Range[uint16], error) {
	// Parse at full width before converting; parseRange[uint16] would wrap
	// values above 65535 before we could validate them.
	parsed, err := parseRange[uint32](nil, values)
	if err != nil {
		return nil, err
	}
	result := make([]ranges.Range[uint16], 0, len(parsed))
	for _, interval := range parsed {
		if interval.Start > interval.End || interval.End > 65535 {
			return nil, fmt.Errorf("invalid port range %d:%d", interval.Start, interval.End)
		}
		result = append(result, ranges.New(uint16(interval.Start), uint16(interval.End)))
	}
	return result, nil
}
