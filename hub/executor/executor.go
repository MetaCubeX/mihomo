package executor

import (
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/outboundgroup"
	"github.com/Dreamacro/clash/component/auth"
	"github.com/Dreamacro/clash/component/dialer"
	G "github.com/Dreamacro/clash/component/geodata"
	"github.com/Dreamacro/clash/component/iface"
	"github.com/Dreamacro/clash/component/profile"
	"github.com/Dreamacro/clash/component/profile/cachefile"
	"github.com/Dreamacro/clash/component/resolver"
	SNI "github.com/Dreamacro/clash/component/sniffer"
	CTLS "github.com/Dreamacro/clash/component/tls"
	"github.com/Dreamacro/clash/component/trie"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
	"github.com/Dreamacro/clash/dns"
	"github.com/Dreamacro/clash/listener"
	authStore "github.com/Dreamacro/clash/listener/auth"
	LC "github.com/Dreamacro/clash/listener/config"
	"github.com/Dreamacro/clash/listener/inner"
	"github.com/Dreamacro/clash/listener/tproxy"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/tunnel"
)

var mux sync.Mutex

func readConfig(path string) ([]byte, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("configuration file %s is empty", path)
	}

	return data, err
}

// Parse config with default config path
func Parse() (*config.Config, error) {
	return ParseWithPath(C.Path.Config())
}

// ParseWithPath parse config with custom config path
func ParseWithPath(path string) (*config.Config, error) {
	buf, err := readConfig(path)
	if err != nil {
		return nil, err
	}

	return ParseWithBytes(buf)
}

// ParseWithBytes config with buffer
func ParseWithBytes(buf []byte) (*config.Config, error) {
	return config.Parse(buf)
}

// ApplyConfig dispatch configure to all parts
func ApplyConfig(cfg *config.Config, force bool) {
	mux.Lock()
	defer mux.Unlock()

	tunnel.OnSuspend()

	CTLS.ResetCertificate()
	for _, c := range cfg.TLS.CustomTrustCert {
		if err := CTLS.AddCertificate(c); err != nil {
			log.Warnln("%s\nadd error: %s", c, err.Error())
		}
	}

	updateUsers(cfg.Users)
	updateProxies(cfg.Proxies, cfg.Providers)
	updateRules(cfg.Rules, cfg.SubRules, cfg.RuleProviders)
	updateSniffer(cfg.Sniffer)
	updateHosts(cfg.Hosts)
	updateGeneral(cfg.General)
	updateDNS(cfg.DNS, cfg.RuleProviders, cfg.General.IPv6)
	updateListeners(cfg.General, cfg.Listeners, force)
	updateIPTables(cfg)
	updateTun(cfg.General)
	updateExperimental(cfg)
	updateTunnels(cfg.Tunnels)

	tunnel.OnInnerLoading()

	initInnerTcp()
	loadProxyProvider(cfg.Providers)
	updateProfile(cfg)
	loadRuleProvider(cfg.RuleProviders)
	runtime.GC()
	tunnel.OnRunning()

	log.SetLevel(cfg.General.LogLevel)
}

func initInnerTcp() {
	inner.New(tunnel.TCPIn())
}

func GetGeneral() *config.General {
	ports := listener.GetPorts()
	var authenticator []string
	if auth := authStore.Authenticator(); auth != nil {
		authenticator = auth.Users()
	}

	general := &config.General{
		Inbound: config.Inbound{
			Port:              ports.Port,
			SocksPort:         ports.SocksPort,
			RedirPort:         ports.RedirPort,
			TProxyPort:        ports.TProxyPort,
			MixedPort:         ports.MixedPort,
			Tun:               listener.GetTunConf(),
			TuicServer:        listener.GetTuicConf(),
			ShadowSocksConfig: ports.ShadowSocksConfig,
			VmessConfig:       ports.VmessConfig,
			Authentication:    authenticator,
			AllowLan:          listener.AllowLan(),
			BindAddress:       listener.BindAddress(),
		},
		Mode:          tunnel.Mode(),
		LogLevel:      log.Level(),
		IPv6:          !resolver.DisableIPv6,
		GeodataLoader: G.LoaderName(),
		Interface:     dialer.DefaultInterface.Load(),
		Sniffing:      tunnel.IsSniffing(),
		TCPConcurrent: dialer.GetTcpConcurrent(),
	}

	return general
}

func updateListeners(general *config.General, listeners map[string]C.InboundListener, force bool) {
	tcpIn := tunnel.TCPIn()
	udpIn := tunnel.UDPIn()
	natTable := tunnel.NatTable()

	listener.PatchInboundListeners(listeners, tcpIn, udpIn, natTable, true)
	if !force {
		return
	}

	allowLan := general.AllowLan
	listener.SetAllowLan(allowLan)

	bindAddress := general.BindAddress
	listener.SetBindAddress(bindAddress)
	listener.ReCreateHTTP(general.Port, tcpIn)
	listener.ReCreateSocks(general.SocksPort, tcpIn, udpIn)
	listener.ReCreateRedir(general.RedirPort, tcpIn, udpIn, natTable)
	listener.ReCreateTProxy(general.TProxyPort, tcpIn, udpIn, natTable)
	listener.ReCreateMixed(general.MixedPort, tcpIn, udpIn)
	listener.ReCreateShadowSocks(general.ShadowSocksConfig, tcpIn, udpIn)
	listener.ReCreateVmess(general.VmessConfig, tcpIn, udpIn)
	listener.ReCreateTuic(LC.TuicServer(general.TuicServer), tcpIn, udpIn)
}

func updateExperimental(c *config.Config) {
}

func updateDNS(c *config.DNS, ruleProvider map[string]provider.RuleProvider, generalIPv6 bool) {
	if !c.Enable {
		resolver.DefaultResolver = nil
		resolver.DefaultHostMapper = nil
		resolver.DefaultLocalServer = nil
		dns.ReCreateServer("", nil, nil)
		return
	}
	policy := make(map[string][]dns.NameServer)
	domainSetPolicies := make(map[provider.RuleProvider][]dns.NameServer)
	for key, nameservers := range c.NameServerPolicy {
		temp := strings.Split(key, ":")
		if len(temp) == 2 {
			prefix := temp[0]
			key := temp[1]
			switch strings.ToLower(prefix) {
			case "rule-set":
				if p, ok := ruleProvider[key]; ok {
					domainSetPolicies[p] = nameservers
				}
			case "geosite":
				// TODO:
			}
		} else {
			policy[key] = nameservers
		}
	}
	cfg := dns.Config{
		Main:         c.NameServer,
		Fallback:     c.Fallback,
		IPv6:         c.IPv6 && generalIPv6,
		IPv6Timeout:  c.IPv6Timeout,
		EnhancedMode: c.EnhancedMode,
		Pool:         c.FakeIPRange,
		Hosts:        c.Hosts,
		FallbackFilter: dns.FallbackFilter{
			GeoIP:     c.FallbackFilter.GeoIP,
			GeoIPCode: c.FallbackFilter.GeoIPCode,
			IPCIDR:    c.FallbackFilter.IPCIDR,
			Domain:    c.FallbackFilter.Domain,
			GeoSite:   c.FallbackFilter.GeoSite,
		},
		Default:         c.DefaultNameserver,
		Policy:          c.NameServerPolicy,
		ProxyServer:     c.ProxyServerNameserver,
		DomainSetPolicy: domainSetPolicies,
	}

	r := dns.NewResolver(cfg)
	pr := dns.NewProxyServerHostResolver(r)
	m := dns.NewEnhancer(cfg)

	// reuse cache of old host mapper
	if old := resolver.DefaultHostMapper; old != nil {
		m.PatchFrom(old.(*dns.ResolverEnhancer))
	}

	resolver.DefaultResolver = r
	resolver.DefaultHostMapper = m

	if pr.Invalid() {
		resolver.ProxyServerHostResolver = pr
	}

	dns.ReCreateServer(c.Listen, r, m)
}

func updateHosts(tree *trie.DomainTrie[resolver.HostValue]) {
	resolver.DefaultHosts = resolver.NewHosts(tree)
}

func updateProxies(proxies map[string]C.Proxy, providers map[string]provider.ProxyProvider) {
	tunnel.UpdateProxies(proxies, providers)
}

func updateRules(rules []C.Rule, subRules map[string][]C.Rule, ruleProviders map[string]provider.RuleProvider) {
	tunnel.UpdateRules(rules, subRules, ruleProviders)
}

func loadProvider(pv provider.Provider) {
	if pv.VehicleType() == provider.Compatible {
		log.Infoln("Start initial compatible provider %s", pv.Name())
	} else {
		log.Infoln("Start initial provider %s", (pv).Name())
	}

	if err := pv.Initial(); err != nil {
		switch pv.Type() {
		case provider.Proxy:
			{
				log.Errorln("initial proxy provider %s error: %v", (pv).Name(), err)
			}
		case provider.Rule:
			{
				log.Errorln("initial rule provider %s error: %v", (pv).Name(), err)
			}

		}
	}
}

func loadRuleProvider(ruleProviders map[string]provider.RuleProvider) {
	wg := sync.WaitGroup{}
	ch := make(chan struct{}, concurrentCount)
	for _, ruleProvider := range ruleProviders {
		ruleProvider := ruleProvider
		wg.Add(1)
		ch <- struct{}{}
		go func() {
			defer func() { <-ch; wg.Done() }()
			loadProvider(ruleProvider)

		}()
	}

	wg.Wait()
}

func loadProxyProvider(proxyProviders map[string]provider.ProxyProvider) {
	// limit concurrent size
	wg := sync.WaitGroup{}
	ch := make(chan struct{}, concurrentCount)
	for _, proxyProvider := range proxyProviders {
		proxyProvider := proxyProvider
		wg.Add(1)
		ch <- struct{}{}
		go func() {
			defer func() { <-ch; wg.Done() }()
			loadProvider(proxyProvider)
		}()
	}

	wg.Wait()
}

func updateTun(general *config.General) {
	if general == nil {
		return
	}
	listener.ReCreateTun(LC.Tun(general.Tun), tunnel.TCPIn(), tunnel.UDPIn())
	listener.ReCreateRedirToTun(general.Tun.RedirectToTun)
}

func updateSniffer(sniffer *config.Sniffer) {
	if sniffer.Enable {
		dispatcher, err := SNI.NewSnifferDispatcher(
			sniffer.Sniffers, sniffer.ForceDomain, sniffer.SkipDomain,
			sniffer.ForceDnsMapping, sniffer.ParsePureIp,
		)
		if err != nil {
			log.Warnln("initial sniffer failed, err:%v", err)
		}

		tunnel.UpdateSniffer(dispatcher)
		log.Infoln("Sniffer is loaded and working")
	} else {
		dispatcher, err := SNI.NewCloseSnifferDispatcher()
		if err != nil {
			log.Warnln("initial sniffer failed, err:%v", err)
		}

		tunnel.UpdateSniffer(dispatcher)
		log.Infoln("Sniffer is closed")
	}
}

func updateTunnels(tunnels []LC.Tunnel) {
	listener.PatchTunnel(tunnels, tunnel.TCPIn(), tunnel.UDPIn())
}

func updateGeneral(general *config.General) {
	tunnel.SetMode(general.Mode)
	tunnel.SetFindProcessMode(general.FindProcessMode)
	resolver.DisableIPv6 = !general.IPv6

	if general.TCPConcurrent {
		dialer.SetTcpConcurrent(general.TCPConcurrent)
		log.Infoln("Use tcp concurrent")
	}

	adapter.UnifiedDelay.Store(general.UnifiedDelay)

	dialer.DefaultInterface.Store(general.Interface)
	dialer.DefaultRoutingMark.Store(int32(general.RoutingMark))
	if general.RoutingMark > 0 {
		log.Infoln("Use routing mark: %#x", general.RoutingMark)
	}

	iface.FlushCache()
	geodataLoader := general.GeodataLoader
	G.SetLoader(geodataLoader)
}

func updateUsers(users []auth.AuthUser) {
	authenticator := auth.NewAuthenticator(users)
	authStore.SetAuthenticator(authenticator)
	if authenticator != nil {
		log.Infoln("Authentication of local server updated")
	}
}

func updateProfile(cfg *config.Config) {
	profileCfg := cfg.Profile

	profile.StoreSelected.Store(profileCfg.StoreSelected)
	if profileCfg.StoreSelected {
		patchSelectGroup(cfg.Proxies)
	}
}

func patchSelectGroup(proxies map[string]C.Proxy) {
	mapping := cachefile.Cache().SelectedMap()
	if mapping == nil {
		return
	}

	for name, proxy := range proxies {
		outbound, ok := proxy.(*adapter.Proxy)
		if !ok {
			continue
		}

		selector, ok := outbound.ProxyAdapter.(outboundgroup.SelectAble)
		if !ok {
			continue
		}

		selected, exist := mapping[name]
		if !exist {
			continue
		}

		selector.ForceSet(selected)
	}
}

func updateIPTables(cfg *config.Config) {
	tproxy.CleanupTProxyIPTables()

	iptables := cfg.IPTables
	if runtime.GOOS != "linux" || !iptables.Enable {
		return
	}

	var err error
	defer func() {
		if err != nil {
			log.Errorln("[IPTABLES] setting iptables failed: %s", err.Error())
			os.Exit(2)
		}
	}()

	if cfg.General.Tun.Enable {
		err = fmt.Errorf("when tun is enabled, iptables cannot be set automatically")
		return
	}

	var (
		inboundInterface = "lo"
		bypass           = iptables.Bypass
		tProxyPort       = cfg.General.TProxyPort
		dnsCfg           = cfg.DNS
	)

	if tProxyPort == 0 {
		err = fmt.Errorf("tproxy-port must be greater than zero")
		return
	}

	if !dnsCfg.Enable {
		err = fmt.Errorf("DNS server must be enable")
		return
	}

	dnsPort, err := netip.ParseAddrPort(dnsCfg.Listen)
	if err != nil {
		err = fmt.Errorf("DNS server must be correct")
		return
	}

	if iptables.InboundInterface != "" {
		inboundInterface = iptables.InboundInterface
	}

	if dialer.DefaultRoutingMark.Load() == 0 {
		dialer.DefaultRoutingMark.Store(2158)
	}

	err = tproxy.SetTProxyIPTables(inboundInterface, bypass, uint16(tProxyPort), dnsPort.Port())
	if err != nil {
		return
	}

	log.Infoln("[IPTABLES] Setting iptables completed")
}

func Shutdown() {
	listener.Cleanup(false)
	tproxy.CleanupTProxyIPTables()
	resolver.StoreFakePoolState()

	log.Warnln("Clash shutting down")
}
