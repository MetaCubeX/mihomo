package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strings"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/adapter/outboundgroup"
	"github.com/Dreamacro/clash/adapter/provider"
	"github.com/Dreamacro/clash/component/auth"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/fakeip"
	"github.com/Dreamacro/clash/component/geodata"
	"github.com/Dreamacro/clash/component/geodata/router"
	_ "github.com/Dreamacro/clash/component/geodata/standard"
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
	providerTypes "github.com/Dreamacro/clash/constant/provider"
	"github.com/Dreamacro/clash/dns"
	"github.com/Dreamacro/clash/listener/tun/ipstack/commons"
	"github.com/Dreamacro/clash/log"
	rewrites "github.com/Dreamacro/clash/rewrite"
	R "github.com/Dreamacro/clash/rule"
	T "github.com/Dreamacro/clash/tunnel"

	"gopkg.in/yaml.v3"
)

// General config
type General struct {
	Inbound
	Controller
	Mode        T.TunnelMode `json:"mode"`
	LogLevel    log.LogLevel `json:"log-level"`
	IPv6        bool         `json:"ipv6"`
	Sniffing    bool         `json:"sniffing"`
	Interface   string       `json:"-"`
	RoutingMark int          `json:"-"`
	Tun         Tun          `json:"tun"`
}

// Inbound config
type Inbound struct {
	Port           int      `json:"port"`
	SocksPort      int      `json:"socks-port"`
	RedirPort      int      `json:"redir-port"`
	TProxyPort     int      `json:"tproxy-port"`
	MixedPort      int      `json:"mixed-port"`
	MitmPort       int      `json:"mitm-port"`
	Authentication []string `json:"authentication"`
	AllowLan       bool     `json:"allow-lan"`
	BindAddress    string   `json:"bind-address"`
}

// Controller config
type Controller struct {
	ExternalController string `json:"-"`
	ExternalUI         string `json:"-"`
	Secret             string `json:"-"`
}

// DNS config
type DNS struct {
	Enable                bool             `yaml:"enable"`
	IPv6                  bool             `yaml:"ipv6"`
	NameServer            []dns.NameServer `yaml:"nameserver"`
	Fallback              []dns.NameServer `yaml:"fallback"`
	FallbackFilter        FallbackFilter   `yaml:"fallback-filter"`
	Listen                string           `yaml:"listen"`
	EnhancedMode          C.DNSMode        `yaml:"enhanced-mode"`
	DefaultNameserver     []dns.NameServer `yaml:"default-nameserver"`
	FakeIPRange           *fakeip.Pool
	Hosts                 *trie.DomainTrie[netip.Addr]
	NameServerPolicy      map[string]dns.NameServer
	ProxyServerNameserver []dns.NameServer
}

// FallbackFilter config
type FallbackFilter struct {
	GeoIP     bool                    `yaml:"geoip"`
	GeoIPCode string                  `yaml:"geoip-code"`
	IPCIDR    []*netip.Prefix         `yaml:"ipcidr"`
	Domain    []string                `yaml:"domain"`
	GeoSite   []*router.DomainMatcher `yaml:"geosite"`
}

// Profile config
type Profile struct {
	StoreSelected bool `yaml:"store-selected"`
	StoreFakeIP   bool `yaml:"store-fake-ip"`
}

// Tun config
type Tun struct {
	Enable              bool          `yaml:"enable" json:"enable"`
	Device              string        `yaml:"device" json:"device"`
	Stack               C.TUNStack    `yaml:"stack" json:"stack"`
	DNSHijack           []C.DNSUrl    `yaml:"dns-hijack" json:"dns-hijack"`
	AutoRoute           bool          `yaml:"auto-route" json:"auto-route"`
	AutoDetectInterface bool          `yaml:"auto-detect-interface" json:"auto-detect-interface"`
	TunAddressPrefix    *netip.Prefix `yaml:"_" json:"_"`
}

// IPTables config
type IPTables struct {
	Enable           bool   `yaml:"enable" json:"enable"`
	InboundInterface string `yaml:"inbound-interface" json:"inbound-interface"`
}

// Mitm config
type Mitm struct {
	Hosts *trie.DomainTrie[bool] `yaml:"hosts" json:"hosts"`
	Rules C.RewriteRule          `yaml:"rules" json:"rules"`
}

// Experimental config
type Experimental struct{}

// Config is clash config manager
type Config struct {
	General      *General
	IPTables     *IPTables
	Mitm         *Mitm
	DNS          *DNS
	Experimental *Experimental
	Hosts        *trie.DomainTrie[netip.Addr]
	Profile      *Profile
	Rules        []C.Rule
	Users        []auth.AuthUser
	Proxies      map[string]C.Proxy
	Providers    map[string]providerTypes.ProxyProvider
}

type RawDNS struct {
	Enable                bool              `yaml:"enable"`
	IPv6                  bool              `yaml:"ipv6"`
	UseHosts              bool              `yaml:"use-hosts"`
	NameServer            []string          `yaml:"nameserver"`
	Fallback              []string          `yaml:"fallback"`
	FallbackFilter        RawFallbackFilter `yaml:"fallback-filter"`
	Listen                string            `yaml:"listen"`
	EnhancedMode          C.DNSMode         `yaml:"enhanced-mode"`
	FakeIPRange           string            `yaml:"fake-ip-range"`
	FakeIPFilter          []string          `yaml:"fake-ip-filter"`
	DefaultNameserver     []string          `yaml:"default-nameserver"`
	NameServerPolicy      map[string]string `yaml:"nameserver-policy"`
	ProxyServerNameserver []string          `yaml:"proxy-server-nameserver"`
}

type RawFallbackFilter struct {
	GeoIP     bool     `yaml:"geoip"`
	GeoIPCode string   `yaml:"geoip-code"`
	IPCIDR    []string `yaml:"ipcidr"`
	Domain    []string `yaml:"domain"`
	GeoSite   []string `yaml:"geosite"`
}

type RawMitm struct {
	Hosts []string `yaml:"hosts" json:"hosts"`
	Rules []string `yaml:"rules" json:"rules"`
}

type RawConfig struct {
	Port               int          `yaml:"port"`
	SocksPort          int          `yaml:"socks-port"`
	RedirPort          int          `yaml:"redir-port"`
	TProxyPort         int          `yaml:"tproxy-port"`
	MixedPort          int          `yaml:"mixed-port"`
	MitmPort           int          `yaml:"mitm-port"`
	Authentication     []string     `yaml:"authentication"`
	AllowLan           bool         `yaml:"allow-lan"`
	BindAddress        string       `yaml:"bind-address"`
	Mode               T.TunnelMode `yaml:"mode"`
	LogLevel           log.LogLevel `yaml:"log-level"`
	IPv6               bool         `yaml:"ipv6"`
	ExternalController string       `yaml:"external-controller"`
	ExternalUI         string       `yaml:"external-ui"`
	Secret             string       `yaml:"secret"`
	Interface          string       `yaml:"interface-name"`
	RoutingMark        int          `yaml:"routing-mark"`
	Sniffing           bool         `yaml:"sniffing"`
	ForceCertVerify    bool         `yaml:"force-cert-verify"`

	ProxyProvider map[string]map[string]any `yaml:"proxy-providers"`
	Hosts         map[string]string         `yaml:"hosts"`
	DNS           RawDNS                    `yaml:"dns"`
	Tun           Tun                       `yaml:"tun"`
	IPTables      IPTables                  `yaml:"iptables"`
	MITM          RawMitm                   `yaml:"mitm"`
	Experimental  Experimental              `yaml:"experimental"`
	Profile       Profile                   `yaml:"profile"`
	Proxy         []map[string]any          `yaml:"proxies"`
	ProxyGroup    []map[string]any          `yaml:"proxy-groups"`
	Rule          []string                  `yaml:"rules"`
}

// Parse config
func Parse(buf []byte) (*Config, error) {
	rawCfg, err := UnmarshalRawConfig(buf)
	if err != nil {
		return nil, err
	}

	return ParseRawConfig(rawCfg)
}

func UnmarshalRawConfig(buf []byte) (*RawConfig, error) {
	// config with default value
	rawCfg := &RawConfig{
		AllowLan:        false,
		Sniffing:        false,
		ForceCertVerify: false,
		BindAddress:     "*",
		Mode:            T.Rule,
		Authentication:  []string{},
		LogLevel:        log.INFO,
		Hosts:           map[string]string{},
		Rule:            []string{},
		Proxy:           []map[string]any{},
		ProxyGroup:      []map[string]any{},
		Tun: Tun{
			Enable: false,
			Device: "",
			Stack:  C.TunGvisor,
			DNSHijack: []C.DNSUrl{ // default hijack all dns lookup
				{
					Network: "udp",
					AddrPort: C.DNSAddrPort{
						AddrPort: netip.MustParseAddrPort("0.0.0.0:53"),
					},
				},
				{
					Network: "tcp",
					AddrPort: C.DNSAddrPort{
						AddrPort: netip.MustParseAddrPort("0.0.0.0:53"),
					},
				},
			},
			AutoRoute:           false,
			AutoDetectInterface: false,
		},
		IPTables: IPTables{
			Enable:           false,
			InboundInterface: "lo",
		},
		DNS: RawDNS{
			Enable:       false,
			UseHosts:     true,
			EnhancedMode: C.DNSMapping,
			FakeIPRange:  "198.18.0.1/16",
			FallbackFilter: RawFallbackFilter{
				GeoIP:     true,
				GeoIPCode: "CN",
				IPCIDR:    []string{},
				GeoSite:   []string{},
			},
			DefaultNameserver: []string{
				"114.114.114.114",
				"223.5.5.5",
			},
			NameServer: []string{ // default if user not set
				"https://120.53.53.53/dns-query",
				"tls://223.5.5.5:853",
			},
		},
		MITM: RawMitm{
			Hosts: []string{},
			Rules: []string{},
		},
		Profile: Profile{
			StoreSelected: true,
		},
	}

	if err := yaml.Unmarshal(buf, rawCfg); err != nil {
		return nil, err
	}

	return rawCfg, nil
}

func ParseRawConfig(rawCfg *RawConfig) (*Config, error) {
	config := &Config{}

	config.Experimental = &rawCfg.Experimental
	config.Profile = &rawCfg.Profile
	config.IPTables = &rawCfg.IPTables

	general, err := parseGeneral(rawCfg)
	if err != nil {
		return nil, err
	}
	config.General = general

	proxies, providers, err := parseProxies(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Proxies = proxies
	config.Providers = providers

	rules, err := parseRules(rawCfg, proxies)
	if err != nil {
		return nil, err
	}
	config.Rules = rules

	hosts, err := parseHosts(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Hosts = hosts

	dnsCfg, err := parseDNS(rawCfg, hosts)
	if err != nil {
		return nil, err
	}
	config.DNS = dnsCfg

	mitm, err := parseMitm(rawCfg.MITM)
	if err != nil {
		return nil, err
	}
	config.Mitm = mitm

	config.Users = parseAuthentication(rawCfg.Authentication)

	return config, nil
}

func parseGeneral(cfg *RawConfig) (*General, error) {
	externalUI := cfg.ExternalUI

	// checkout externalUI exist
	if externalUI != "" {
		externalUI = C.Path.Resolve(externalUI)

		if _, err := os.Stat(externalUI); os.IsNotExist(err) {
			return nil, fmt.Errorf("external-ui: %s not exist", externalUI)
		}
	}

	if cfg.Tun.Enable && cfg.Tun.AutoDetectInterface {
		outboundInterface, err := commons.GetAutoDetectInterface()
		if err != nil && cfg.Interface == "" {
			return nil, fmt.Errorf("get auto detect interface fail: %w", err)
		}

		if outboundInterface != "" {
			cfg.Interface = outboundInterface
		}
	}

	dialer.DefaultInterface.Store(cfg.Interface)

	return &General{
		Inbound: Inbound{
			Port:        cfg.Port,
			SocksPort:   cfg.SocksPort,
			RedirPort:   cfg.RedirPort,
			TProxyPort:  cfg.TProxyPort,
			MixedPort:   cfg.MixedPort,
			MitmPort:    cfg.MitmPort,
			AllowLan:    cfg.AllowLan,
			BindAddress: cfg.BindAddress,
		},
		Controller: Controller{
			ExternalController: cfg.ExternalController,
			ExternalUI:         cfg.ExternalUI,
			Secret:             cfg.Secret,
		},
		Mode:        cfg.Mode,
		LogLevel:    cfg.LogLevel,
		IPv6:        cfg.IPv6,
		Interface:   cfg.Interface,
		RoutingMark: cfg.RoutingMark,
		Sniffing:    cfg.Sniffing,
		Tun:         cfg.Tun,
	}, nil
}

func parseProxies(cfg *RawConfig) (proxies map[string]C.Proxy, providersMap map[string]providerTypes.ProxyProvider, err error) {
	proxies = make(map[string]C.Proxy)
	providersMap = make(map[string]providerTypes.ProxyProvider)
	proxiesConfig := cfg.Proxy
	groupsConfig := cfg.ProxyGroup
	providersConfig := cfg.ProxyProvider
	forceCertVerify := cfg.ForceCertVerify

	var proxyList []string

	proxies["DIRECT"] = adapter.NewProxy(outbound.NewDirect())
	proxies["REJECT"] = adapter.NewProxy(outbound.NewReject())
	proxyList = append(proxyList, "DIRECT", "REJECT")

	// parse proxy
	for idx, mapping := range proxiesConfig {
		proxy, err := adapter.ParseProxy(mapping, forceCertVerify)
		if err != nil {
			return nil, nil, fmt.Errorf("proxy %d: %w", idx, err)
		}

		if _, exist := proxies[proxy.Name()]; exist {
			return nil, nil, fmt.Errorf("proxy %s is the duplicate name", proxy.Name())
		}
		proxies[proxy.Name()] = proxy
		proxyList = append(proxyList, proxy.Name())
	}

	// keep the original order of ProxyGroups in config file
	for idx, mapping := range groupsConfig {
		groupName, existName := mapping["name"].(string)
		if !existName {
			return nil, nil, fmt.Errorf("proxy group %d: missing name", idx)
		}
		proxyList = append(proxyList, groupName)
	}

	// check if any loop exists and sort the ProxyGroups
	if err := proxyGroupsDagSort(groupsConfig); err != nil {
		return nil, nil, err
	}

	// parse and initial providers
	for name, mapping := range providersConfig {
		if name == provider.ReservedName {
			return nil, nil, fmt.Errorf("can not defined a provider called `%s`", provider.ReservedName)
		}

		pd, err := provider.ParseProxyProvider(name, mapping, forceCertVerify)
		if err != nil {
			return nil, nil, fmt.Errorf("parse proxy provider %s error: %w", name, err)
		}

		providersMap[name] = pd
	}

	for _, proxyProvider := range providersMap {
		log.Infoln("Start initial proxy provider %s", proxyProvider.Name())
		if err := proxyProvider.Initial(); err != nil {
			return nil, nil, fmt.Errorf("initial proxy provider %s error: %w", proxyProvider.Name(), err)
		}
	}

	// parse proxy group
	for idx, mapping := range groupsConfig {
		group, err := outboundgroup.ParseProxyGroup(mapping, proxies, providersMap)
		if err != nil {
			return nil, nil, fmt.Errorf("proxy group[%d]: %w", idx, err)
		}

		groupName := group.Name()
		if _, exist := proxies[groupName]; exist {
			return nil, nil, fmt.Errorf("proxy group %s: the duplicate name", groupName)
		}

		proxies[groupName] = adapter.NewProxy(group)
	}

	// initial compatible provider
	for _, pd := range providersMap {
		if pd.VehicleType() != providerTypes.Compatible {
			continue
		}

		log.Infoln("Start initial compatible provider %s", pd.Name())
		if err := pd.Initial(); err != nil {
			return nil, nil, err
		}
	}

	var ps []C.Proxy
	for _, v := range proxyList {
		ps = append(ps, proxies[v])
	}
	hc := provider.NewHealthCheck(ps, "", 0, true)
	pd, _ := provider.NewCompatibleProvider(provider.ReservedName, ps, hc)
	providersMap[provider.ReservedName] = pd

	global := outboundgroup.NewSelector(
		&outboundgroup.GroupCommonOption{
			Name: "GLOBAL",
		},
		[]providerTypes.ProxyProvider{pd},
	)
	proxies["GLOBAL"] = adapter.NewProxy(global)
	return proxies, providersMap, nil
}

func parseRules(cfg *RawConfig, proxies map[string]C.Proxy) ([]C.Rule, error) {
	rulesConfig := cfg.Rule

	var rules []C.Rule

	// parse rules
	for idx, line := range rulesConfig {
		rule := trimArr(strings.Split(line, ","))
		var (
			payload  string
			target   string
			params   []string
			ruleName = strings.ToUpper(rule[0])
		)

		l := len(rule)

		if l < 2 {
			return nil, fmt.Errorf("rules[%d] [%s] error: format invalid", idx, line)
		}

		if l < 4 {
			rule = append(rule, make([]string, 4-l)...)
		}

		if ruleName == "MATCH" {
			l = 2
		}

		if l >= 3 {
			l = 3
			payload = rule[1]
		}

		target = rule[l-1]
		params = rule[l:]

		if _, ok := proxies[target]; !ok {
			return nil, fmt.Errorf("rules[%d] [%s] error: proxy [%s] not found", idx, line, target)
		}

		params = trimArr(params)

		parsed, parseErr := R.ParseRule(ruleName, payload, target, params)
		if parseErr != nil {
			return nil, fmt.Errorf("rules[%d] [%s] error: %s", idx, line, parseErr.Error())
		}

		rules = append(rules, parsed)
	}

	runtime.GC()

	return rules, nil
}

func parseHosts(cfg *RawConfig) (*trie.DomainTrie[netip.Addr], error) {
	tree := trie.New[netip.Addr]()

	// add default hosts
	if err := tree.Insert("localhost", netip.AddrFrom4([4]byte{127, 0, 0, 1})); err != nil {
		log.Errorln("insert localhost to host error: %s", err.Error())
	}

	if len(cfg.Hosts) != 0 {
		for domain, ipStr := range cfg.Hosts {
			ip, err := netip.ParseAddr(ipStr)
			if err != nil {
				return nil, fmt.Errorf("%s is not a valid IP", ipStr)
			}
			_ = tree.Insert(domain, ip)
		}
	}

	// add mitm.clash hosts
	if err := tree.Insert("mitm.clash", netip.AddrFrom4([4]byte{1, 2, 3, 4})); err != nil {
		log.Errorln("insert mitm.clash to host error: %s", err.Error())
	}

	return tree, nil
}

func hostWithDefaultPort(host string, defPort string) (string, error) {
	if !strings.Contains(host, ":") {
		host += ":"
	}

	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		return "", err
	}

	if port == "" {
		port = defPort
	}

	return net.JoinHostPort(hostname, port), nil
}

func parseNameServer(servers []string) ([]dns.NameServer, error) {
	var nameservers []dns.NameServer

	for idx, server := range servers {
		// parse without scheme .e.g 8.8.8.8:53
		if !strings.Contains(server, "://") {
			server = "udp://" + server
		}
		u, err := url.Parse(server)
		if err != nil {
			return nil, fmt.Errorf("DNS NameServer[%d] format error: %s", idx, err.Error())
		}

		var addr, dnsNetType string
		switch u.Scheme {
		case "udp":
			addr, err = hostWithDefaultPort(u.Host, "53")
			dnsNetType = "" // UDP
		case "tcp":
			addr, err = hostWithDefaultPort(u.Host, "53")
			dnsNetType = "tcp" // TCP
		case "tls":
			addr, err = hostWithDefaultPort(u.Host, "853")
			dnsNetType = "tcp-tls" // DNS over TLS
		case "https":
			clearURL := url.URL{Scheme: "https", Host: u.Host, Path: u.Path}
			addr = clearURL.String()
			dnsNetType = "https" // DNS over HTTPS
		case "dhcp":
			addr = u.Host
			dnsNetType = "dhcp" // UDP from DHCP
		default:
			return nil, fmt.Errorf("DNS NameServer[%d] unsupport scheme: %s", idx, u.Scheme)
		}

		if err != nil {
			return nil, fmt.Errorf("DNS NameServer[%d] format error: %s", idx, err.Error())
		}

		nameservers = append(
			nameservers,
			dns.NameServer{
				Net:          dnsNetType,
				Addr:         addr,
				ProxyAdapter: u.Fragment,
				Interface:    dialer.DefaultInterface.Load(),
			},
		)
	}
	return nameservers, nil
}

func parseNameServerPolicy(nsPolicy map[string]string) (map[string]dns.NameServer, error) {
	policy := map[string]dns.NameServer{}

	for domain, server := range nsPolicy {
		nameservers, err := parseNameServer([]string{server})
		if err != nil {
			return nil, err
		}
		if _, valid := trie.ValidAndSplitDomain(domain); !valid {
			return nil, fmt.Errorf("DNS ResoverRule invalid domain: %s", domain)
		}
		policy[domain] = nameservers[0]
	}

	return policy, nil
}

func parseFallbackIPCIDR(ips []string) ([]*netip.Prefix, error) {
	var ipNets []*netip.Prefix

	for idx, ip := range ips {
		ipnet, err := netip.ParsePrefix(ip)
		if err != nil {
			return nil, fmt.Errorf("DNS FallbackIP[%d] format error: %s", idx, err.Error())
		}
		ipNets = append(ipNets, &ipnet)
	}

	return ipNets, nil
}

func parseFallbackGeoSite(countries []string) ([]*router.DomainMatcher, error) {
	var sites []*router.DomainMatcher
	for _, country := range countries {
		matcher, recordsCount, err := geodata.LoadProviderByCode(country)
		if err != nil {
			return nil, err
		}

		sites = append(sites, matcher)

		cont := fmt.Sprintf("%d", recordsCount)
		if recordsCount == 0 {
			cont = "from cache"
		}
		log.Infoln("Start initial GeoSite dns fallback filter `%s`, records: %s", country, cont)
	}
	runtime.GC()
	return sites, nil
}

func parseDNS(rawCfg *RawConfig, hosts *trie.DomainTrie[netip.Addr]) (*DNS, error) {
	cfg := rawCfg.DNS
	if cfg.Enable && len(cfg.NameServer) == 0 {
		return nil, fmt.Errorf("if DNS configuration is turned on, NameServer cannot be empty")
	}

	dnsCfg := &DNS{
		Enable:       cfg.Enable,
		Listen:       cfg.Listen,
		IPv6:         cfg.IPv6,
		EnhancedMode: cfg.EnhancedMode,
		FallbackFilter: FallbackFilter{
			IPCIDR:  []*netip.Prefix{},
			GeoSite: []*router.DomainMatcher{},
		},
	}
	var err error
	if dnsCfg.NameServer, err = parseNameServer(cfg.NameServer); err != nil {
		return nil, err
	}

	if dnsCfg.Fallback, err = parseNameServer(cfg.Fallback); err != nil {
		return nil, err
	}

	if dnsCfg.NameServerPolicy, err = parseNameServerPolicy(cfg.NameServerPolicy); err != nil {
		return nil, err
	}

	if dnsCfg.ProxyServerNameserver, err = parseNameServer(cfg.ProxyServerNameserver); err != nil {
		return nil, err
	}

	if len(cfg.DefaultNameserver) == 0 {
		return nil, errors.New("default nameserver should have at least one nameserver")
	}
	if dnsCfg.DefaultNameserver, err = parseNameServer(cfg.DefaultNameserver); err != nil {
		return nil, err
	}
	// check default nameserver is pure ip addr
	for _, ns := range dnsCfg.DefaultNameserver {
		host, _, err := net.SplitHostPort(ns.Addr)
		if err != nil || net.ParseIP(host) == nil {
			return nil, errors.New("default nameserver should be pure IP")
		}
	}

	if cfg.EnhancedMode == C.DNSFakeIP {
		ipnet, err := netip.ParsePrefix(cfg.FakeIPRange)
		if err != nil {
			return nil, err
		}

		var host *trie.DomainTrie[bool]
		// fake ip skip host filter
		if len(cfg.FakeIPFilter) != 0 {
			host = trie.New[bool]()
			for _, domain := range cfg.FakeIPFilter {
				_ = host.Insert(domain, true)
			}
		}

		if len(dnsCfg.Fallback) != 0 {
			if host == nil {
				host = trie.New[bool]()
			}
			for _, fb := range dnsCfg.Fallback {
				if net.ParseIP(fb.Addr) != nil {
					continue
				}
				_ = host.Insert(fb.Addr, true)
			}
		}

		pool, err := fakeip.New(fakeip.Options{
			IPNet:       &ipnet,
			Size:        1000,
			Host:        host,
			Persistence: rawCfg.Profile.StoreFakeIP,
		})
		if err != nil {
			return nil, err
		}

		dnsCfg.FakeIPRange = pool
	}

	if len(cfg.Fallback) != 0 {
		dnsCfg.FallbackFilter.GeoIP = cfg.FallbackFilter.GeoIP
		dnsCfg.FallbackFilter.GeoIPCode = cfg.FallbackFilter.GeoIPCode
		if fallbackip, err := parseFallbackIPCIDR(cfg.FallbackFilter.IPCIDR); err == nil {
			dnsCfg.FallbackFilter.IPCIDR = fallbackip
		}
		dnsCfg.FallbackFilter.Domain = cfg.FallbackFilter.Domain
		fallbackGeoSite, err := parseFallbackGeoSite(cfg.FallbackFilter.GeoSite)
		if err != nil {
			return nil, fmt.Errorf("load GeoSite dns fallback filter error, %w", err)
		}
		dnsCfg.FallbackFilter.GeoSite = fallbackGeoSite
	}

	if cfg.UseHosts {
		dnsCfg.Hosts = hosts
	}

	return dnsCfg, nil
}

func parseAuthentication(rawRecords []string) []auth.AuthUser {
	var users []auth.AuthUser
	for _, line := range rawRecords {
		if user, pass, found := strings.Cut(line, ":"); found {
			users = append(users, auth.AuthUser{User: user, Pass: pass})
		}
	}
	return users
}

func parseMitm(rawMitm RawMitm) (*Mitm, error) {
	var (
		req []C.Rewrite
		res []C.Rewrite
	)

	for _, line := range rawMitm.Rules {
		rule, err := rewrites.ParseRewrite(line)
		if err != nil {
			return nil, fmt.Errorf("parse rewrite rule failure: %w", err)
		}

		if rule.RuleType() == C.MitmResponseHeader || rule.RuleType() == C.MitmResponseBody {
			res = append(res, rule)
		} else {
			req = append(req, rule)
		}
	}

	hosts := trie.New[bool]()

	if len(rawMitm.Hosts) != 0 {
		for _, domain := range rawMitm.Hosts {
			_ = hosts.Insert(domain, true)
		}
	}

	_ = hosts.Insert("mitm.clash", true)

	return &Mitm{
		Hosts: hosts,
		Rules: rewrites.NewRewriteRules(req, res),
	}, nil
}
