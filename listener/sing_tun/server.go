package sing_tun

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/iface"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/sing"
	"github.com/Dreamacro/clash/log"

	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/ranges"
)

var InterfaceName = "Meta"

type Listener struct {
	closed  bool
	options config.Tun
	handler *ListenerHandler

	tunIf    tun.Tun
	tunStack tun.Stack

	networkUpdateMonitor    tun.NetworkUpdateMonitor
	defaultInterfaceMonitor tun.DefaultInterfaceMonitor
	packageManager          tun.PackageManager
}

func CalculateInterfaceName(name string) (tunName string) {
	if runtime.GOOS == "darwin" {
		tunName = "utun"
	} else if name != "" {
		tunName = name
		return
	} else {
		tunName = "tun"
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}
	var tunIndex int
	for _, netInterface := range interfaces {
		if strings.HasPrefix(netInterface.Name, tunName) {
			index, parseErr := strconv.ParseInt(netInterface.Name[len(tunName):], 10, 16)
			if parseErr == nil {
				tunIndex = int(index) + 1
			}
		}
	}
	tunName = F.ToString(tunName, tunIndex)
	return
}

func New(options config.Tun, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) (l *Listener, err error) {
	tunName := options.Device
	if tunName == "" {
		tunName = CalculateInterfaceName(InterfaceName)
	}
	tunMTU := options.MTU
	if tunMTU == 0 {
		tunMTU = 9000
	}
	var udpTimeout int64
	if options.UDPTimeout != 0 {
		udpTimeout = options.UDPTimeout
	} else {
		udpTimeout = int64(C.DefaultUDPTimeout.Seconds())
	}
	includeUID := uidToRange(options.IncludeUID)
	if len(options.IncludeUIDRange) > 0 {
		var err error
		includeUID, err = parseRange(includeUID, options.IncludeUIDRange)
		if err != nil {
			return nil, E.Cause(err, "parse include_uid_range")
		}
	}
	excludeUID := uidToRange(options.ExcludeUID)
	if len(options.ExcludeUIDRange) > 0 {
		var err error
		excludeUID, err = parseRange(excludeUID, options.ExcludeUIDRange)
		if err != nil {
			return nil, E.Cause(err, "parse exclude_uid_range")
		}
	}

	var dnsAdds []netip.AddrPort

	for _, d := range options.DNSHijack {
		dnsAdds = append(dnsAdds, d)
	}
	for _, a := range options.Inet4Address {
		addrPort := netip.AddrPortFrom(a.Build().Addr().Next(), 53)
		dnsAdds = append(dnsAdds, addrPort)
	}
	for _, a := range options.Inet6Address {
		addrPort := netip.AddrPortFrom(a.Build().Addr().Next(), 53)
		dnsAdds = append(dnsAdds, addrPort)
	}

	handler := &ListenerHandler{
		ListenerHandler: sing.ListenerHandler{
			TcpIn: tcpIn,
			UdpIn: udpIn,
			Type:  C.TUN,
		},
		DnsAdds: dnsAdds,
	}
	l = &Listener{
		closed:  false,
		options: options,
		handler: handler,
	}
	defer func() {
		if err != nil {
			l.Close()
			l = nil
		}
	}()

	networkUpdateMonitor, err := tun.NewNetworkUpdateMonitor(handler)
	if err != nil {
		err = E.Cause(err, "create NetworkUpdateMonitor")
		return
	}
	err = networkUpdateMonitor.Start()
	if err != nil {
		err = E.Cause(err, "start NetworkUpdateMonitor")
		return
	}
	l.networkUpdateMonitor = networkUpdateMonitor

	defaultInterfaceMonitor, err := tun.NewDefaultInterfaceMonitor(networkUpdateMonitor, tun.DefaultInterfaceMonitorOptions{})
	if err != nil {
		err = E.Cause(err, "create DefaultInterfaceMonitor")
		return
	}
	defaultInterfaceMonitor.RegisterCallback(func(event int) error {
		targetInterface := dialer.DefaultInterface.Load()
		autoDetectInterfaceName := defaultInterfaceMonitor.DefaultInterfaceName(netip.IPv4Unspecified())
		if autoDetectInterfaceName != "" && autoDetectInterfaceName != "<nil>" {
			targetInterface = autoDetectInterfaceName
		} else {
			log.Warnln("Auto detect interface name is empty.")
		}
		if old := dialer.DefaultInterface.Load(); old != targetInterface {
			log.Warnln("[TUN] default interface changed by monitor, %s => %s", old, targetInterface)

			dialer.DefaultInterface.Store(targetInterface)

			iface.FlushCache()
		}
		return nil
	})
	err = defaultInterfaceMonitor.Start()
	if err != nil {
		err = E.Cause(err, "start DefaultInterfaceMonitor")
		return
	}
	l.defaultInterfaceMonitor = defaultInterfaceMonitor

	tunOptions := tun.Options{
		Name:               tunName,
		MTU:                tunMTU,
		Inet4Address:       common.Map(options.Inet4Address, config.ListenPrefix.Build),
		Inet6Address:       common.Map(options.Inet6Address, config.ListenPrefix.Build),
		AutoRoute:          options.AutoRoute,
		StrictRoute:        options.StrictRoute,
		IncludeUID:         includeUID,
		ExcludeUID:         excludeUID,
		IncludeAndroidUser: options.IncludeAndroidUser,
		IncludePackage:     options.IncludePackage,
		ExcludePackage:     options.ExcludePackage,
		InterfaceMonitor:   defaultInterfaceMonitor,
		TableIndex:         2022,
	}

	err = l.buildAndroidRules(&tunOptions)
	if err != nil {
		err = E.Cause(err, "build android rules")
		return
	}
	tunIf, err := tun.Open(tunOptions)
	if err != nil {
		err = E.Cause(err, "configure tun interface")
		return
	}
	l.tunIf = tunIf
	l.tunStack, err = tun.NewStack(options.Stack, tun.StackOptions{
		Context:                context.TODO(),
		Tun:                    tunIf,
		MTU:                    tunOptions.MTU,
		Name:                   tunOptions.Name,
		Inet4Address:           tunOptions.Inet4Address,
		Inet6Address:           tunOptions.Inet6Address,
		EndpointIndependentNat: options.EndpointIndependentNat,
		UDPTimeout:             udpTimeout,
		Handler:                handler,
		Logger:                 sing.Logger,
	})
	if err != nil {
		return
	}
	err = l.tunStack.Start()
	if err != nil {
		return
	}
	log.Infoln("Tun adapter listening at: %s(%s,%s), mtu: %d, auto route: %v, ip stack: %s",
		tunName, tunOptions.Inet4Address, tunOptions.Inet6Address, tunMTU, options.AutoRoute, options.Stack)
	return
}

func uidToRange(uidList []uint32) []ranges.Range[uint32] {
	return common.Map(uidList, func(uid uint32) ranges.Range[uint32] {
		return ranges.NewSingle(uid)
	})
}

func parseRange(uidRanges []ranges.Range[uint32], rangeList []string) ([]ranges.Range[uint32], error) {
	for _, uidRange := range rangeList {
		if !strings.Contains(uidRange, ":") {
			return nil, E.New("missing ':' in range: ", uidRange)
		}
		subIndex := strings.Index(uidRange, ":")
		if subIndex == 0 {
			return nil, E.New("missing range start: ", uidRange)
		} else if subIndex == len(uidRange)-1 {
			return nil, E.New("missing range end: ", uidRange)
		}
		var start, end uint64
		var err error
		start, err = strconv.ParseUint(uidRange[:subIndex], 10, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range start")
		}
		end, err = strconv.ParseUint(uidRange[subIndex+1:], 10, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range end")
		}
		uidRanges = append(uidRanges, ranges.New(uint32(start), uint32(end)))
	}
	return uidRanges, nil
}

func (l *Listener) Close() {
	l.closed = true
	_ = common.Close(
		l.tunStack,
		l.tunIf,
		l.defaultInterfaceMonitor,
		l.networkUpdateMonitor,
		l.packageManager,
	)
}

func (l *Listener) Config() config.Tun {
	return l.options
}
