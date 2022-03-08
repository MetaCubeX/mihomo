package executor

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/outboundgroup"
	"github.com/Dreamacro/clash/component/auth"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/iface"
	"github.com/Dreamacro/clash/component/profile"
	"github.com/Dreamacro/clash/component/profile/cachefile"
	"github.com/Dreamacro/clash/component/resolver"
	"github.com/Dreamacro/clash/component/trie"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
	"github.com/Dreamacro/clash/dns"
	P "github.com/Dreamacro/clash/listener"
	authStore "github.com/Dreamacro/clash/listener/auth"
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

	log.SetLevel(log.DEBUG)

	updateUsers(cfg.Users)
	updateProxies(cfg.Proxies, cfg.Providers)
	updateRules(cfg.Rules)
	updateHosts(cfg.Hosts)
	updateProfile(cfg)
	updateDNS(cfg.DNS, cfg.Tun)
	updateGeneral(cfg.General, force)
	updateIPTables(cfg.DNS, cfg.General.TProxyPort, cfg.General.Interface, cfg.Tun.Enable)
	updateTun(cfg.Tun)
	updateExperimental(cfg)

	log.SetLevel(cfg.General.LogLevel)
}

func GetGeneral() *config.General {
	ports := P.GetPorts()
	authenticator := []string{}
	if auth := authStore.Authenticator(); auth != nil {
		authenticator = auth.Users()
	}

	general := &config.General{
		Inbound: config.Inbound{
			Port:           ports.Port,
			SocksPort:      ports.SocksPort,
			RedirPort:      ports.RedirPort,
			TProxyPort:     ports.TProxyPort,
			MixedPort:      ports.MixedPort,
			Authentication: authenticator,
			AllowLan:       P.AllowLan(),
			BindAddress:    P.BindAddress(),
		},
		Mode:     tunnel.Mode(),
		LogLevel: log.Level(),
		IPv6:     !resolver.DisableIPv6,
	}

	return general
}

func updateExperimental(c *config.Config) {}

func updateDNS(c *config.DNS, t *config.Tun) {
	cfg := dns.Config{
		Main:         c.NameServer,
		Fallback:     c.Fallback,
		IPv6:         c.IPv6,
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
		Default: c.DefaultNameserver,
		Policy:  c.NameServerPolicy,
	}

	r := dns.NewResolver(cfg)
	mr := dns.NewMainResolver(r)
	m := dns.NewEnhancer(cfg)

	// reuse cache of old host mapper
	if old := resolver.DefaultHostMapper; old != nil {
		m.PatchFrom(old.(*dns.ResolverEnhancer))
	}

	resolver.DefaultResolver = r
	resolver.MainResolver = mr
	resolver.DefaultHostMapper = m

	if t.Enable {
		resolver.DefaultLocalServer = dns.NewLocalServer(r, m)
	}

	if c.Enable {
		dns.ReCreateServer(c.Listen, r, m)
	} else {
		if !t.Enable {
			resolver.DefaultResolver = nil
			resolver.MainResolver = nil
			resolver.DefaultHostMapper = nil
			resolver.DefaultLocalServer = nil
		}
		dns.ReCreateServer("", nil, nil)
	}
}

func updateHosts(tree *trie.DomainTrie) {
	resolver.DefaultHosts = tree
}

func updateProxies(proxies map[string]C.Proxy, providers map[string]provider.ProxyProvider) {
	tunnel.UpdateProxies(proxies, providers)
}

func updateRules(rules []C.Rule) {
	tunnel.UpdateRules(rules)
}

func updateTun(tun *config.Tun) {
	P.ReCreateTun(tun, tunnel.TCPIn(), tunnel.UDPIn())
}

func updateGeneral(general *config.General, force bool) {
	tunnel.SetMode(general.Mode)
	resolver.DisableIPv6 = !general.IPv6

	dialer.DefaultInterface.Store(general.Interface)
	if dialer.DefaultInterface.Load() != "" {
		log.Infoln("Use interface name: %s", general.Interface)
	}

	if general.RoutingMark > 0 || (general.RoutingMark == 0 && general.TProxyPort == 0) {
		dialer.DefaultRoutingMark.Store(int32(general.RoutingMark))
		if general.RoutingMark > 0 {
			log.Infoln("Use routing mark: %#x", general.RoutingMark)
		}
	}

	iface.FlushCache()

	if !force {
		return
	}

	allowLan := general.AllowLan
	P.SetAllowLan(allowLan)

	bindAddress := general.BindAddress
	P.SetBindAddress(bindAddress)

	tcpIn := tunnel.TCPIn()
	udpIn := tunnel.UDPIn()

	P.ReCreateHTTP(general.Port, tcpIn)
	P.ReCreateSocks(general.SocksPort, tcpIn, udpIn)
	P.ReCreateRedir(general.RedirPort, tcpIn, udpIn)
	P.ReCreateTProxy(general.TProxyPort, tcpIn, udpIn)
	P.ReCreateMixed(general.MixedPort, tcpIn, udpIn)
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

		selector, ok := outbound.ProxyAdapter.(*outboundgroup.Selector)
		if !ok {
			continue
		}

		selected, exist := mapping[name]
		if !exist {
			continue
		}

		selector.Set(selected)
	}
}

func updateIPTables(dns *config.DNS, tProxyPort int, interfaceName string, tunEnable bool) {
	tproxy.CleanUpTProxyLinuxIPTables()

	if runtime.GOOS != "linux" || tProxyPort == 0 {
		return
	}

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Setting iptables failed: %s", err.Error())
			os.Exit(2)
		}
	}()

	if !dns.Enable || dns.Listen == "" {
		err = fmt.Errorf("DNS server must be enable")
		return
	}

	if tunEnable {
		err = fmt.Errorf("TUN device must be disabe")
		return
	}

	_, dnsPortStr, err := net.SplitHostPort(dns.Listen)
	if dnsPortStr == "0" || dnsPortStr == "" || err != nil {
		return
	}

	dnsPort, err := strconv.Atoi(dnsPortStr)
	if err != nil {
		return
	}

	if dialer.DefaultRoutingMark.Load() == 0 {
		dialer.DefaultRoutingMark.Store(2158)
	}

	err = tproxy.SetTProxyLinuxIPTables(interfaceName, tProxyPort, dnsPort)
}

func Cleanup() {
	if runtime.GOOS == "linux" {
		tproxy.CleanUpTProxyLinuxIPTables()
	}
}
