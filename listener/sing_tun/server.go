package sing_tun

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"
	"golang.org/x/exp/constraints"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/control"
	E "github.com/metacubex/sing/common/exceptions"
	F "github.com/metacubex/sing/common/format"
	"github.com/metacubex/sing/common/ranges"

	"go4.org/netipx"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

var InterfaceName = "Meta"
var EnforceBindInterface = false

type Listener struct {
	closed  bool
	options LC.Tun
	handler *ListenerHandler
	tunName string
	addrStr string

	tunIf    tun.Tun
	tunStack tun.Stack

	networkUpdateMonitor    tun.NetworkUpdateMonitor
	defaultInterfaceMonitor tun.DefaultInterfaceMonitor
	packageManager          tun.PackageManager
	autoRedirect            tun.AutoRedirect
	autoRedirectOutputMark  int32

	cDialerInterfaceFinder dialer.InterfaceFinder

	ruleUpdateCallbackCloser io.Closer
	ruleUpdateMutex          sync.Mutex
	routeAddressMap          map[string]*netipx.IPSet
	routeExcludeAddressMap   map[string]*netipx.IPSet
	routeAddressSet          []*netipx.IPSet
	routeExcludeAddressSet   []*netipx.IPSet

	dnsServerIp []string
}

var emptyAddressSet = []*netipx.IPSet{{}}

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
	tunIndex := 0
	indexArr := make([]int, 0, len(interfaces))
	for _, netInterface := range interfaces {
		if strings.HasPrefix(netInterface.Name, tunName) {
			index, parseErr := strconv.ParseInt(netInterface.Name[len(tunName):], 10, 16)
			if parseErr == nil {
				indexArr = append(indexArr, int(index))
			}
		}
	}
	slices.Sort(indexArr)
	indexArr = slices.Compact(indexArr)
	for _, index := range indexArr {
		if index == tunIndex {
			tunIndex += 1
		} else { // indexArr already sorted and distinct, so this tunIndex nobody used
			break
		}
	}
	tunName = F.ToString(tunName, tunIndex)
	return
}

func checkTunName(tunName string) (ok bool) {
	defer func() {
		if !ok {
			log.Warnln("[TUN] Unsupported tunName(%s) in %s, force regenerate by ourselves.", tunName, runtime.GOOS)
		}
	}()
	if runtime.GOOS == "darwin" {
		if len(tunName) <= 4 {
			return false
		}
		if tunName[:4] != "utun" {
			return false
		}
		if _, parseErr := strconv.ParseInt(tunName[4:], 10, 16); parseErr != nil {
			return false
		}
	}
	return true
}

func New(options LC.Tun, tunnel C.Tunnel, additions ...inbound.Addition) (l *Listener, err error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-TUN"),
			inbound.WithSpecialRules(""),
		}
	}
	ctx := context.TODO()
	rpTunnel := tunnel.(P.Tunnel)
	if options.GSOMaxSize == 0 {
		options.GSOMaxSize = 65536
	}
	if !supportRedirect {
		options.AutoRedirect = false
	}
	tunName := options.Device
	if options.FileDescriptor == 0 && (tunName == "" || !checkTunName(tunName)) {
		tunName = CalculateInterfaceName(InterfaceName)
		options.Device = tunName
	}
	routeAddress := options.RouteAddress
	if len(options.Inet4RouteAddress) > 0 {
		routeAddress = append(routeAddress, options.Inet4RouteAddress...)
	}
	if len(options.Inet6RouteAddress) > 0 {
		routeAddress = append(routeAddress, options.Inet6RouteAddress...)
	}
	inet4RouteAddress := common.Filter(routeAddress, func(it netip.Prefix) bool {
		return it.Addr().Is4()
	})
	inet6RouteAddress := common.Filter(routeAddress, func(it netip.Prefix) bool {
		return it.Addr().Is6()
	})
	routeExcludeAddress := options.RouteExcludeAddress
	if len(options.Inet4RouteExcludeAddress) > 0 {
		routeExcludeAddress = append(routeExcludeAddress, options.Inet4RouteExcludeAddress...)
	}
	if len(options.Inet6RouteExcludeAddress) > 0 {
		routeExcludeAddress = append(routeExcludeAddress, options.Inet6RouteExcludeAddress...)
	}
	inet4RouteExcludeAddress := common.Filter(routeExcludeAddress, func(it netip.Prefix) bool {
		return it.Addr().Is4()
	})
	inet6RouteExcludeAddress := common.Filter(routeExcludeAddress, func(it netip.Prefix) bool {
		return it.Addr().Is6()
	})
	tunMTU := options.MTU
	if tunMTU == 0 {
		tunMTU = 9000
	}
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Second * time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = sing.UDPTimeout
	}
	tableIndex := options.IPRoute2TableIndex
	if tableIndex == 0 {
		tableIndex = tun.DefaultIPRoute2TableIndex
	}
	ruleIndex := options.IPRoute2RuleIndex
	if ruleIndex == 0 {
		ruleIndex = tun.DefaultIPRoute2RuleIndex
	}
	inputMark := options.AutoRedirectInputMark
	if inputMark == 0 {
		inputMark = tun.DefaultAutoRedirectInputMark
	}
	outputMark := options.AutoRedirectOutputMark
	if outputMark == 0 {
		outputMark = tun.DefaultAutoRedirectOutputMark
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
	excludeSrcPort := uidToRange(options.ExcludeSrcPort)
	if len(options.ExcludeSrcPortRange) > 0 {
		var err error
		excludeSrcPort, err = parseRange(excludeSrcPort, options.ExcludeSrcPortRange)
		if err != nil {
			return nil, E.Cause(err, "parse exclude_src_port_range")
		}
	}
	excludeDstPort := uidToRange(options.ExcludeDstPort)
	if len(options.ExcludeDstPortRange) > 0 {
		var err error
		excludeDstPort, err = parseRange(excludeDstPort, options.ExcludeDstPortRange)
		if err != nil {
			return nil, E.Cause(err, "parse exclude_dst_port_range")
		}
	}

	var dnsAdds []netip.AddrPort

	for _, d := range options.DNSHijack {
		if _, after, ok := strings.Cut(d, "://"); ok {
			d = after
		}
		d = strings.Replace(d, "any", "0.0.0.0", 1)
		addrPort, err := netip.ParseAddrPort(d)
		if err != nil {
			return nil, fmt.Errorf("parse dns-hijack url error: %w", err)
		}

		dnsAdds = append(dnsAdds, addrPort)
	}

	var dnsServerIp []string
	for _, a := range options.Inet4Address {
		addrPort := netip.AddrPortFrom(a.Addr().Next(), 53)
		dnsServerIp = append(dnsServerIp, a.Addr().Next().String())
		dnsAdds = append(dnsAdds, addrPort)
	}
	for _, a := range options.Inet6Address {
		addrPort := netip.AddrPortFrom(a.Addr().Next(), 53)
		dnsServerIp = append(dnsServerIp, a.Addr().Next().String())
		dnsAdds = append(dnsAdds, addrPort)
	}

	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.TUN,
		Additions: additions,
	})
	if err != nil {
		return nil, err
	}

	handler := &ListenerHandler{
		ListenerHandler:       h,
		DnsAdds:               dnsAdds,
		DisableICMPForwarding: options.DisableICMPForwarding,
	}
	l = &Listener{
		closed:  false,
		options: options,
		handler: handler,
		tunName: tunName,
	}
	defer func() {
		if err != nil {
			l.Close()
			l = nil
		}
	}()

	interfaceFinder := DefaultInterfaceFinder

	var networkUpdateMonitor tun.NetworkUpdateMonitor
	var defaultInterfaceMonitor tun.DefaultInterfaceMonitor
	if options.AutoRoute || options.AutoDetectInterface { // don't start NetworkUpdateMonitor because netlink banned by google on Android14+
		networkUpdateMonitor, err = tun.NewNetworkUpdateMonitor(log.SingLogger)
		if err != nil {
			err = E.Cause(err, "create NetworkUpdateMonitor")
			return
		}
		l.networkUpdateMonitor = networkUpdateMonitor
		err = networkUpdateMonitor.Start()
		if err != nil {
			err = E.Cause(err, "start NetworkUpdateMonitor")
			return
		}

		overrideAndroidVPN := true
		if disable, _ := strconv.ParseBool(os.Getenv("DISABLE_OVERRIDE_ANDROID_VPN")); disable {
			overrideAndroidVPN = false
		}
		defaultInterfaceMonitor, err = tun.NewDefaultInterfaceMonitor(networkUpdateMonitor, log.SingLogger, tun.DefaultInterfaceMonitorOptions{InterfaceFinder: interfaceFinder, OverrideAndroidVPN: overrideAndroidVPN})
		if err != nil {
			err = E.Cause(err, "create DefaultInterfaceMonitor")
			return
		}
		l.defaultInterfaceMonitor = defaultInterfaceMonitor
		defaultInterfaceMonitor.RegisterCallback(func(defaultInterface *control.Interface, event int) {
			if defaultInterface != nil {
				log.Warnln("[TUN] default interface changed by monitor, => %s", defaultInterface.Name)
			} else {
				log.Errorln("[TUN] default interface lost by monitor")
			}
			iface.FlushCache()
			resolver.ResetConnection() // reset resolver's connection after default interface changed
		})
		err = defaultInterfaceMonitor.Start()
		if err != nil {
			err = E.Cause(err, "start DefaultInterfaceMonitor")
			return
		}

		if options.AutoDetectInterface {
			l.cDialerInterfaceFinder = &cDialerInterfaceFinder{
				tunName:                 tunName,
				defaultInterfaceMonitor: defaultInterfaceMonitor,
			}
			if !dialer.DefaultInterfaceFinder.CompareAndSwap(nil, l.cDialerInterfaceFinder) {
				err = E.New("not allowed two tun listener using auto-detect-interface")
				return
			}
		}
	}

	tunOptions := tun.Options{
		Name:                     tunName,
		MTU:                      tunMTU,
		GSO:                      options.GSO,
		Inet4Address:             options.Inet4Address,
		Inet6Address:             options.Inet6Address,
		AutoRoute:                options.AutoRoute,
		IPRoute2TableIndex:       tableIndex,
		IPRoute2RuleIndex:        ruleIndex,
		AutoRedirectInputMark:    inputMark,
		AutoRedirectOutputMark:   outputMark,
		Inet4LoopbackAddress:     common.Filter(options.LoopbackAddress, netip.Addr.Is4),
		Inet6LoopbackAddress:     common.Filter(options.LoopbackAddress, netip.Addr.Is6),
		StrictRoute:              options.StrictRoute,
		Inet4RouteAddress:        inet4RouteAddress,
		Inet6RouteAddress:        inet6RouteAddress,
		Inet4RouteExcludeAddress: inet4RouteExcludeAddress,
		Inet6RouteExcludeAddress: inet6RouteExcludeAddress,
		IncludeInterface:         options.IncludeInterface,
		ExcludeInterface:         options.ExcludeInterface,
		IncludeUID:               includeUID,
		ExcludeUID:               excludeUID,
		ExcludeSrcPort:           excludeSrcPort,
		ExcludeDstPort:           excludeDstPort,
		IncludeAndroidUser:       options.IncludeAndroidUser,
		IncludePackage:           options.IncludePackage,
		ExcludePackage:           options.ExcludePackage,
		FileDescriptor:           options.FileDescriptor,
		InterfaceMonitor:         defaultInterfaceMonitor,
		EXP_RecvMsgX:             options.RecvMsgX,
		EXP_SendMsgX:             options.SendMsgX,
	}

	if options.AutoRedirect {
		l.routeAddressMap = make(map[string]*netipx.IPSet)
		l.routeExcludeAddressMap = make(map[string]*netipx.IPSet)

		if !options.AutoRoute {
			return nil, E.New("`auto-route` is required by `auto-redirect`")
		}
		disableNFTables, dErr := strconv.ParseBool(os.Getenv("DISABLE_NFTABLES"))
		l.autoRedirect, err = tun.NewAutoRedirect(tun.AutoRedirectOptions{
			TunOptions:             &tunOptions,
			Context:                ctx,
			Handler:                handler.TypeMutation(C.REDIR),
			Logger:                 log.SingLogger,
			NetworkMonitor:         l.networkUpdateMonitor,
			InterfaceFinder:        interfaceFinder,
			TableName:              "mihomo",
			DisableNFTables:        dErr == nil && disableNFTables,
			RouteAddressSet:        &l.routeAddressSet,
			RouteExcludeAddressSet: &l.routeExcludeAddressSet,
		})
		if err != nil {
			err = E.Cause(err, "initialize auto redirect")
			return
		}

		var markMode bool
		for _, routeAddressSet := range options.RouteAddressSet {
			rp, loaded := rpTunnel.RuleProviders()[routeAddressSet]
			if !loaded {
				err = E.New("parse route-address-set: rule-set not found: ", routeAddressSet)
				return
			}
			l.updateRule(rp, false, false)
			markMode = true
		}
		for _, routeExcludeAddressSet := range options.RouteExcludeAddressSet {
			rp, loaded := rpTunnel.RuleProviders()[routeExcludeAddressSet]
			if !loaded {
				err = E.New("parse route-exclude_address-set: rule-set not found: ", routeExcludeAddressSet)
				return
			}
			l.updateRule(rp, true, false)
			markMode = true
		}
		if markMode {
			tunOptions.AutoRedirectMarkMode = true
		}

	}

	err = l.buildAndroidRules(&tunOptions)
	if err != nil {
		err = E.Cause(err, "build android rules")
		return
	}
	tunIf, err := tunNew(tunOptions)
	if err != nil {
		err = E.Cause(err, "configure tun interface")
		return
	}

	l.dnsServerIp = dnsServerIp
	// after tun.New sing-tun has set DNS to TUN interface
	resolver.AddSystemDnsBlacklist(dnsServerIp...)

	stackOptions := tun.StackOptions{
		Context:                ctx,
		Tun:                    tunIf,
		TunOptions:             tunOptions,
		EndpointIndependentNat: options.EndpointIndependentNat,
		UDPTimeout:             udpTimeout,
		Handler:                handler,
		Logger:                 log.SingLogger,
		InterfaceFinder:        interfaceFinder,
		EnforceBindInterface:   EnforceBindInterface,
	}

	if options.FileDescriptor > 0 {
		if tunName, err := getTunnelName(int32(options.FileDescriptor)); err != nil {
			stackOptions.TunOptions.Name = tunName
			stackOptions.ForwarderBindInterface = true
		}
	}
	l.tunIf = tunIf

	tunStack, err := tun.NewStack(strings.ToLower(options.Stack.String()), stackOptions)
	if err != nil {
		return
	}

	err = tunStack.Start()
	if err != nil {
		return
	}
	l.tunStack = tunStack

	if l.autoRedirect != nil {
		if len(l.options.RouteAddressSet) > 0 && len(l.routeAddressSet) == 0 {
			l.routeAddressSet = emptyAddressSet // without this we can't call UpdateRouteAddressSet after Start
		}
		if len(l.options.RouteExcludeAddressSet) > 0 && len(l.routeExcludeAddressSet) == 0 {
			l.routeExcludeAddressSet = emptyAddressSet // without this we can't call UpdateRouteAddressSet after Start
		}
		err = l.autoRedirect.Start()
		if err != nil {
			err = E.Cause(err, "auto redirect")
			return
		}
		if tunOptions.AutoRedirectMarkMode {
			l.autoRedirectOutputMark = int32(outputMark)
			if !dialer.DefaultRoutingMark.CompareAndSwap(0, l.autoRedirectOutputMark) {
				err = E.New("not allowed setting global routing-mark when working with autoRedirectMarkMode")
				return
			}
			l.autoRedirect.UpdateRouteAddressSet()
			l.ruleUpdateCallbackCloser = rpTunnel.RuleUpdateCallback().Register(l.ruleUpdateCallback)
		}
	}

	//l.openAndroidHotspot(tunOptions)

	if !l.options.AutoDetectInterface {
		resolver.ResetConnection()
	}

	if options.FileDescriptor != 0 {
		tunName = fmt.Sprintf("%s(fd=%d)", tunName, options.FileDescriptor)
	}
	l.addrStr = fmt.Sprintf("%s(%s,%s), mtu: %d, auto route: %v, auto redir: %v, ip stack: %s",
		tunName, tunOptions.Inet4Address, tunOptions.Inet6Address, tunMTU, options.AutoRoute, options.AutoRedirect, options.Stack)
	return
}

func (l *Listener) ruleUpdateCallback(ruleProvider P.RuleProvider) {
	name := ruleProvider.Name()
	if slices.Contains(l.options.RouteAddressSet, name) {
		l.updateRule(ruleProvider, false, true)
		return
	}
	if slices.Contains(l.options.RouteExcludeAddressSet, name) {
		l.updateRule(ruleProvider, true, true)
		return
	}
}

type toIpCidr interface {
	ToIpCidr() *netipx.IPSet
}

func (l *Listener) updateRule(ruleProvider P.RuleProvider, exclude bool, update bool) {
	l.ruleUpdateMutex.Lock()
	defer l.ruleUpdateMutex.Unlock()
	name := ruleProvider.Name()
	switch rp := ruleProvider.Strategy().(type) {
	case toIpCidr:
		if !exclude {
			ipCidr := rp.ToIpCidr()
			if ipCidr != nil {
				l.routeAddressMap[name] = ipCidr
			} else {
				delete(l.routeAddressMap, name)
			}
			l.routeAddressSet = maps.Values(l.routeAddressMap)
		} else {
			ipCidr := rp.ToIpCidr()
			if ipCidr != nil {
				l.routeExcludeAddressMap[name] = ipCidr
			} else {
				delete(l.routeExcludeAddressMap, name)
			}
			l.routeExcludeAddressSet = maps.Values(l.routeExcludeAddressMap)
		}
	default:
		return
	}
	if update && l.autoRedirect != nil {
		l.autoRedirect.UpdateRouteAddressSet()
	}
}

func (l *Listener) OnReload() {
	if l.autoRedirectOutputMark != 0 {
		dialer.DefaultRoutingMark.CompareAndSwap(0, l.autoRedirectOutputMark)
	}
	if l.cDialerInterfaceFinder != nil {
		dialer.DefaultInterfaceFinder.CompareAndSwap(nil, l.cDialerInterfaceFinder)
	}
}

type cDialerInterfaceFinder struct {
	tunName                 string
	defaultInterfaceMonitor tun.DefaultInterfaceMonitor
}

func (d *cDialerInterfaceFinder) DefaultInterfaceName(destination netip.Addr) string {
	if netInterface, _ := DefaultInterfaceFinder.ByAddr(destination); netInterface != nil {
		return netInterface.Name
	}
	if netInterface := d.defaultInterfaceMonitor.DefaultInterface(); netInterface != nil {
		return netInterface.Name
	}
	return ""
}

func (d *cDialerInterfaceFinder) FindInterfaceName(destination netip.Addr) string {
	for _, dest := range []netip.Addr{destination, netip.IPv4Unspecified(), netip.IPv6Unspecified()} {
		autoDetectInterfaceName := d.DefaultInterfaceName(dest)
		if autoDetectInterfaceName == d.tunName {
			log.Warnln("[TUN] Auto detect interface for %s get same name with tun", destination.String())
		} else if autoDetectInterfaceName == "" || autoDetectInterfaceName == "<nil>" {
			log.Warnln("[TUN] Auto detect interface for %s get empty name.", destination.String())
		} else {
			log.Debugln("[TUN] Auto detect interface for %s --> %s", destination, autoDetectInterfaceName)
			return autoDetectInterfaceName
		}
	}
	log.Warnln("[TUN] Auto detect interface for %s failed, return '<invalid>' to avoid lookback", destination)
	return "<invalid>"
}

func uidToRange[T constraints.Integer](uidList []T) []ranges.Range[T] {
	return common.Map(uidList, func(uid T) ranges.Range[T] {
		return ranges.NewSingle(uid)
	})
}

func parseRange[T constraints.Integer](uidRanges []ranges.Range[T], rangeList []string) ([]ranges.Range[T], error) {
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
		start, err = strconv.ParseUint(uidRange[:subIndex], 0, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range start")
		}
		end, err = strconv.ParseUint(uidRange[subIndex+1:], 0, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range end")
		}
		uidRanges = append(uidRanges, ranges.New(T(start), T(end)))
	}
	return uidRanges, nil
}

func (l *Listener) Close() error {
	l.closed = true
	resolver.RemoveSystemDnsBlacklist(l.dnsServerIp...)
	if l.autoRedirectOutputMark != 0 {
		dialer.DefaultRoutingMark.CompareAndSwap(l.autoRedirectOutputMark, 0)
	}
	if l.cDialerInterfaceFinder != nil {
		dialer.DefaultInterfaceFinder.CompareAndSwap(l.cDialerInterfaceFinder, nil)
	}
	return common.Close(
		l.ruleUpdateCallbackCloser,
		l.tunStack,
		l.tunIf,
		l.autoRedirect,
		l.defaultInterfaceMonitor,
		l.networkUpdateMonitor,
		l.packageManager,
	)
}

func (l *Listener) Config() LC.Tun {
	return l.options
}

func (l *Listener) Address() string {
	return l.addrStr
}
