package config

import (
	"container/list"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Dreamacro/clash/common/utils"
	R "github.com/Dreamacro/clash/rules"
	RP "github.com/Dreamacro/clash/rules/provider"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/adapter/outboundgroup"
	"github.com/Dreamacro/clash/adapter/provider"
	"github.com/Dreamacro/clash/component/auth"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/fakeip"
	"github.com/Dreamacro/clash/component/geodata"
	"github.com/Dreamacro/clash/component/geodata/router"
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
	providerTypes "github.com/Dreamacro/clash/constant/provider"
	"github.com/Dreamacro/clash/constant/sniffer"
	snifferTypes "github.com/Dreamacro/clash/constant/sniffer"
	"github.com/Dreamacro/clash/dns"
	"github.com/Dreamacro/clash/log"
	T "github.com/Dreamacro/clash/tunnel"

	"gopkg.in/yaml.v3"
)

// General config
type General struct {
	Inbound
	Controller
	Mode          T.TunnelMode `json:"mode"`
	UnifiedDelay  bool
	LogLevel      log.LogLevel `json:"log-level"`
	IPv6          bool         `json:"ipv6"`
	Interface     string       `json:"interface-name"`
	RoutingMark   int          `json:"-"`
	GeodataMode   bool         `json:"geodata-mode"`
	GeodataLoader string       `json:"geodata-loader"`
	TCPConcurrent bool         `json:"tcp-concurrent"`
	EnableProcess bool         `json:"enable-process"`
	Tun           Tun          `json:"tun"`
	Sniffing      bool         `json:"sniffing"`
	EBpf          EBpf         `json:"-"`
}

// Inbound config
type Inbound struct {
	Port           int      `json:"port"`
	SocksPort      int      `json:"socks-port"`
	RedirPort      int      `json:"redir-port"`
	TProxyPort     int      `json:"tproxy-port"`
	MixedPort      int      `json:"mixed-port"`
	Authentication []string `json:"authentication"`
	AllowLan       bool     `json:"allow-lan"`
	BindAddress    string   `json:"bind-address"`
	InboundTfo     bool     `json:"inbound-tfo"`
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
	PreferH3              bool             `yaml:"prefer-h3"`
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
	Enable              bool             `yaml:"enable" json:"enable"`
	Device              string           `yaml:"device" json:"device"`
	Stack               C.TUNStack       `yaml:"stack" json:"stack"`
	DNSHijack           []netip.AddrPort `yaml:"dns-hijack" json:"dns-hijack"`
	AutoRoute           bool             `yaml:"auto-route" json:"auto-route"`
	AutoDetectInterface bool             `yaml:"auto-detect-interface" json:"auto-detect-interface"`
	RedirectToTun       []string         `yaml:"-" json:"-"`

	MTU                    uint32         `yaml:"mtu" json:"mtu,omitempty"`
	Inet4Address           []ListenPrefix `yaml:"inet4-address" json:"inet4_address,omitempty"`
	Inet6Address           []ListenPrefix `yaml:"inet6-address" json:"inet6_address,omitempty"`
	StrictRoute            bool           `yaml:"strict-route" json:"strict_route,omitempty"`
	Inet4RouteAddress      []ListenPrefix `yaml:"inet4_route_address" json:"inet4_route_address,omitempty"`
	Inet6RouteAddress      []ListenPrefix `yaml:"inet6_route_address" json:"inet6_route_address,omitempty"`
	IncludeUID             []uint32       `yaml:"include-uid" json:"include_uid,omitempty"`
	IncludeUIDRange        []string       `yaml:"include-uid-range" json:"include_uid_range,omitempty"`
	ExcludeUID             []uint32       `yaml:"exclude-uid" json:"exclude_uid,omitempty"`
	ExcludeUIDRange        []string       `yaml:"exclude-uid-range" json:"exclude_uid_range,omitempty"`
	IncludeAndroidUser     []int          `yaml:"include-android-user" json:"include_android_user,omitempty"`
	IncludePackage         []string       `yaml:"include-package" json:"include_package,omitempty"`
	ExcludePackage         []string       `yaml:"exclude-package" json:"exclude_package,omitempty"`
	EndpointIndependentNat bool           `yaml:"endpoint-independent-nat" json:"endpoint_independent_nat,omitempty"`
	UDPTimeout             int64          `yaml:"udp-timeout" json:"udp_timeout,omitempty"`
}

type ListenPrefix netip.Prefix

func (p ListenPrefix) MarshalJSON() ([]byte, error) {
	prefix := netip.Prefix(p)
	if !prefix.IsValid() {
		return json.Marshal(nil)
	}
	return json.Marshal(prefix.String())
}

func (p ListenPrefix) MarshalYAML() (interface{}, error) {
	prefix := netip.Prefix(p)
	if !prefix.IsValid() {
		return nil, nil
	}
	return prefix.String(), nil
}

func (p *ListenPrefix) UnmarshalJSON(bytes []byte) error {
	var value string
	err := json.Unmarshal(bytes, &value)
	if err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return err
	}
	*p = ListenPrefix(prefix)
	return nil
}

func (p *ListenPrefix) UnmarshalYAML(node *yaml.Node) error {
	var value string
	err := node.Decode(&value)
	if err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return err
	}
	*p = ListenPrefix(prefix)
	return nil
}

func (p ListenPrefix) Build() netip.Prefix {
	return netip.Prefix(p)
}

// IPTables config
type IPTables struct {
	Enable           bool     `yaml:"enable" json:"enable"`
	InboundInterface string   `yaml:"inbound-interface" json:"inbound-interface"`
	Bypass           []string `yaml:"bypass" json:"bypass"`
}

type Sniffer struct {
	Enable          bool
	Sniffers        []sniffer.Type
	Reverses        *trie.DomainTrie[bool]
	ForceDomain     *trie.DomainTrie[bool]
	SkipDomain      *trie.DomainTrie[bool]
	Ports           *[]utils.Range[uint16]
	ForceDnsMapping bool
	ParsePureIp     bool
}

// Experimental config
type Experimental struct {
	Fingerprints []string `yaml:"fingerprints"`
}

// Config is clash config manager
type Config struct {
	General       *General
	Tun           *Tun
	IPTables      *IPTables
	DNS           *DNS
	Experimental  *Experimental
	Hosts         *trie.DomainTrie[netip.Addr]
	Profile       *Profile
	Rules         []C.Rule
	SubRules      *map[string][]C.Rule
	Users         []auth.AuthUser
	Proxies       map[string]C.Proxy
	Providers     map[string]providerTypes.ProxyProvider
	RuleProviders map[string]providerTypes.RuleProvider
	Sniffer       *Sniffer
}

type RawDNS struct {
	Enable                bool              `yaml:"enable"`
	PreferH3              bool              `yaml:"prefer-h3"`
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

type RawTun struct {
	Enable              bool       `yaml:"enable" json:"enable"`
	Device              string     `yaml:"device" json:"device"`
	Stack               C.TUNStack `yaml:"stack" json:"stack"`
	DNSHijack           []string   `yaml:"dns-hijack" json:"dns-hijack"`
	AutoRoute           bool       `yaml:"auto-route" json:"auto-route"`
	AutoDetectInterface bool       `yaml:"auto-detect-interface"`
	RedirectToTun       []string   `yaml:"-" json:"-"`

	MTU uint32 `yaml:"mtu" json:"mtu,omitempty"`
	//Inet4Address           []ListenPrefix `yaml:"inet4-address" json:"inet4_address,omitempty"`
	Inet6Address           []ListenPrefix `yaml:"inet6-address" json:"inet6_address,omitempty"`
	StrictRoute            bool           `yaml:"strict-route" json:"strict_route,omitempty"`
	Inet4RouteAddress      []ListenPrefix `yaml:"inet4_route_address" json:"inet4_route_address,omitempty"`
	Inet6RouteAddress      []ListenPrefix `yaml:"inet6_route_address" json:"inet6_route_address,omitempty"`
	IncludeUID             []uint32       `yaml:"include-uid" json:"include_uid,omitempty"`
	IncludeUIDRange        []string       `yaml:"include-uid-range" json:"include_uid_range,omitempty"`
	ExcludeUID             []uint32       `yaml:"exclude-uid" json:"exclude_uid,omitempty"`
	ExcludeUIDRange        []string       `yaml:"exclude-uid-range" json:"exclude_uid_range,omitempty"`
	IncludeAndroidUser     []int          `yaml:"include-android-user" json:"include_android_user,omitempty"`
	IncludePackage         []string       `yaml:"include-package" json:"include_package,omitempty"`
	ExcludePackage         []string       `yaml:"exclude-package" json:"exclude_package,omitempty"`
	EndpointIndependentNat bool           `yaml:"endpoint-independent-nat" json:"endpoint_independent_nat,omitempty"`
	UDPTimeout             int64          `yaml:"udp-timeout" json:"udp_timeout,omitempty"`
}

type RawConfig struct {
	Port               int          `yaml:"port"`
	SocksPort          int          `yaml:"socks-port"`
	RedirPort          int          `yaml:"redir-port"`
	TProxyPort         int          `yaml:"tproxy-port"`
	MixedPort          int          `yaml:"mixed-port"`
	InboundTfo         bool         `yaml:"inbound-tfo"`
	Authentication     []string     `yaml:"authentication"`
	AllowLan           bool         `yaml:"allow-lan"`
	BindAddress        string       `yaml:"bind-address"`
	Mode               T.TunnelMode `yaml:"mode"`
	UnifiedDelay       bool         `yaml:"unified-delay"`
	LogLevel           log.LogLevel `yaml:"log-level"`
	IPv6               bool         `yaml:"ipv6"`
	ExternalController string       `yaml:"external-controller"`
	ExternalUI         string       `yaml:"external-ui"`
	Secret             string       `yaml:"secret"`
	Interface          string       `yaml:"interface-name"`
	RoutingMark        int          `yaml:"routing-mark"`
	GeodataMode        bool         `yaml:"geodata-mode"`
	GeodataLoader      string       `yaml:"geodata-loader"`
	TCPConcurrent      bool         `yaml:"tcp-concurrent" json:"tcp-concurrent"`
	EnableProcess      bool         `yaml:"enable-process" json:"enable-process"`

	Sniffer       RawSniffer                `yaml:"sniffer"`
	ProxyProvider map[string]map[string]any `yaml:"proxy-providers"`
	RuleProvider  map[string]map[string]any `yaml:"rule-providers"`
	Hosts         map[string]string         `yaml:"hosts"`
	DNS           RawDNS                    `yaml:"dns"`
	Tun           RawTun                    `yaml:"tun"`
	EBpf          EBpf                      `yaml:"ebpf"`
	IPTables      IPTables                  `yaml:"iptables"`
	Experimental  Experimental              `yaml:"experimental"`
	Profile       Profile                   `yaml:"profile"`
	GeoXUrl       RawGeoXUrl                `yaml:"geox-url"`
	Proxy         []map[string]any          `yaml:"proxies"`
	ProxyGroup    []map[string]any          `yaml:"proxy-groups"`
	Rule          []string                  `yaml:"rules"`
	SubRules      map[string][]string       `yaml:"sub-rules"`
}

type RawGeoXUrl struct {
	GeoIp   string `yaml:"geoip" json:"geoip"`
	Mmdb    string `yaml:"mmdb" json:"mmdb"`
	GeoSite string `yaml:"geosite" json:"geosite"`
}

type RawSniffer struct {
	Enable          bool     `yaml:"enable" json:"enable"`
	Sniffing        []string `yaml:"sniffing" json:"sniffing"`
	ForceDomain     []string `yaml:"force-domain" json:"force-domain"`
	SkipDomain      []string `yaml:"skip-domain" json:"skip-domain"`
	Ports           []string `yaml:"port-whitelist" json:"port-whitelist"`
	ForceDnsMapping bool     `yaml:"force-dns-mapping" json:"force-dns-mapping"`
	ParsePureIp     bool     `yaml:"parse-pure-ip" json:"parse-pure-ip"`
}

// EBpf config
type EBpf struct {
	RedirectToTun []string `yaml:"redirect-to-tun" json:"redirect-to-tun"`
	AutoRedir     []string `yaml:"auto-redir" json:"auto-redir"`
}

var (
	GroupsList             = list.New()
	ProxiesList            = list.New()
	ParsingProxiesCallback func(groupsList *list.List, proxiesList *list.List)
)

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
		AllowLan:       false,
		BindAddress:    "*",
		IPv6:           true,
		Mode:           T.Rule,
		GeodataMode:    C.GeodataMode,
		GeodataLoader:  "memconservative",
		UnifiedDelay:   false,
		Authentication: []string{},
		LogLevel:       log.INFO,
		Hosts:          map[string]string{},
		Rule:           []string{},
		Proxy:          []map[string]any{},
		ProxyGroup:     []map[string]any{},
		TCPConcurrent:  false,
		EnableProcess:  false,
		Tun: RawTun{
			Enable:              false,
			Device:              "",
			Stack:               C.TunGvisor,
			DNSHijack:           []string{"0.0.0.0:53"}, // default hijack all dns query
			AutoRoute:           true,
			AutoDetectInterface: true,
			Inet6Address:        []ListenPrefix{ListenPrefix(netip.MustParsePrefix("fdfe:dcba:9876::1/126"))},
		},
		EBpf: EBpf{
			RedirectToTun: []string{},
			AutoRedir:     []string{},
		},
		IPTables: IPTables{
			Enable:           false,
			InboundInterface: "lo",
			Bypass:           []string{},
		},
		DNS: RawDNS{
			Enable:       false,
			IPv6:         false,
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
				"8.8.8.8",
				"1.0.0.1",
			},
			NameServer: []string{
				"https://doh.pub/dns-query",
				"tls://223.5.5.5:853",
			},
			FakeIPFilter: []string{
				"dns.msftnsci.com",
				"www.msftnsci.com",
				"www.msftconnecttest.com",
			},
		},
		Sniffer: RawSniffer{
			Enable:          false,
			Sniffing:        []string{},
			ForceDomain:     []string{},
			SkipDomain:      []string{},
			Ports:           []string{},
			ForceDnsMapping: true,
			ParsePureIp:     true,
		},
		Profile: Profile{
			StoreSelected: true,
		},
		GeoXUrl: RawGeoXUrl{
			GeoIp:   "https://ghproxy.com/https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geoip.dat",
			Mmdb:    "https://ghproxy.com/https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb",
			GeoSite: "https://ghproxy.com/https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite.dat",
		},
	}

	if err := yaml.Unmarshal(buf, rawCfg); err != nil {
		return nil, err
	}

	return rawCfg, nil
}

func ParseRawConfig(rawCfg *RawConfig) (*Config, error) {
	config := &Config{}
	log.Infoln("Start initial configuration in progress") //Segment finished in xxm
	startTime := time.Now()
	config.Experimental = &rawCfg.Experimental
	config.Profile = &rawCfg.Profile
	config.IPTables = &rawCfg.IPTables

	general, err := parseGeneral(rawCfg)
	if err != nil {
		return nil, err
	}
	config.General = general

	dialer.DefaultInterface.Store(config.General.Interface)

	proxies, providers, err := parseProxies(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Proxies = proxies
	config.Providers = providers

	subRules, ruleProviders, err := parseSubRules(rawCfg, proxies)
	if err != nil {
		return nil, err
	}
	config.SubRules = subRules
	config.RuleProviders = ruleProviders

	rules, err := parseRules(rawCfg, proxies, subRules)
	if err != nil {
		return nil, err
	}
	config.Rules = rules

	hosts, err := parseHosts(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Hosts = hosts

	dnsCfg, err := parseDNS(rawCfg, hosts, rules)
	if err != nil {
		return nil, err
	}
	config.DNS = dnsCfg

	tunCfg, err := parseTun(rawCfg.Tun, config.General, dnsCfg)
	if err != nil {
		return nil, err
	}
	config.Tun = tunCfg

	config.Users = parseAuthentication(rawCfg.Authentication)

	config.Sniffer, err = parseSniffer(rawCfg.Sniffer)
	if err != nil {
		return nil, err
	}

	elapsedTime := time.Since(startTime) / time.Millisecond                     // duration in ms
	log.Infoln("Initial configuration complete, total time: %dms", elapsedTime) //Segment finished in xxm
	return config, nil
}

func parseGeneral(cfg *RawConfig) (*General, error) {
	externalUI := cfg.ExternalUI
	geodata.SetLoader(cfg.GeodataLoader)
	// checkout externalUI exist
	if externalUI != "" {
		externalUI = C.Path.Resolve(externalUI)

		if _, err := os.Stat(externalUI); os.IsNotExist(err) {
			return nil, fmt.Errorf("external-ui: %s not exist", externalUI)
		}
	}
	cfg.Tun.RedirectToTun = cfg.EBpf.RedirectToTun
	return &General{
		Inbound: Inbound{
			Port:        cfg.Port,
			SocksPort:   cfg.SocksPort,
			RedirPort:   cfg.RedirPort,
			TProxyPort:  cfg.TProxyPort,
			MixedPort:   cfg.MixedPort,
			AllowLan:    cfg.AllowLan,
			BindAddress: cfg.BindAddress,
			InboundTfo:  cfg.InboundTfo,
		},
		Controller: Controller{
			ExternalController: cfg.ExternalController,
			ExternalUI:         cfg.ExternalUI,
			Secret:             cfg.Secret,
		},
		UnifiedDelay:  cfg.UnifiedDelay,
		Mode:          cfg.Mode,
		LogLevel:      cfg.LogLevel,
		IPv6:          cfg.IPv6,
		Interface:     cfg.Interface,
		RoutingMark:   cfg.RoutingMark,
		GeodataMode:   cfg.GeodataMode,
		GeodataLoader: cfg.GeodataLoader,
		TCPConcurrent: cfg.TCPConcurrent,
		EnableProcess: cfg.EnableProcess,
		EBpf:          cfg.EBpf,
	}, nil
}

func parseProxies(cfg *RawConfig) (proxies map[string]C.Proxy, providersMap map[string]providerTypes.ProxyProvider, err error) {
	proxies = make(map[string]C.Proxy)
	providersMap = make(map[string]providerTypes.ProxyProvider)
	proxiesConfig := cfg.Proxy
	groupsConfig := cfg.ProxyGroup
	providersConfig := cfg.ProxyProvider

	var proxyList []string
	proxiesList := list.New()
	groupsList := list.New()

	proxies["DIRECT"] = adapter.NewProxy(outbound.NewDirect())
	proxies["REJECT"] = adapter.NewProxy(outbound.NewReject())
	proxies["COMPATIBLE"] = adapter.NewProxy(outbound.NewCompatible())
	proxies["PASS"] = adapter.NewProxy(outbound.NewPass())
	proxyList = append(proxyList, "DIRECT", "REJECT")

	// parse proxy
	for idx, mapping := range proxiesConfig {
		proxy, err := adapter.ParseProxy(mapping)
		if err != nil {
			return nil, nil, fmt.Errorf("proxy %d: %w", idx, err)
		}

		if _, exist := proxies[proxy.Name()]; exist {
			return nil, nil, fmt.Errorf("proxy %s is the duplicate name", proxy.Name())
		}
		proxies[proxy.Name()] = proxy
		proxyList = append(proxyList, proxy.Name())
		proxiesList.PushBack(mapping)
	}

	// keep the original order of ProxyGroups in config file
	for idx, mapping := range groupsConfig {
		groupName, existName := mapping["name"].(string)
		if !existName {
			return nil, nil, fmt.Errorf("proxy group %d: missing name", idx)
		}
		proxyList = append(proxyList, groupName)
		groupsList.PushBack(mapping)
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

		pd, err := provider.ParseProxyProvider(name, mapping)
		if err != nil {
			return nil, nil, fmt.Errorf("parse proxy provider %s error: %w", name, err)
		}

		providersMap[name] = pd
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

	var ps []C.Proxy
	for _, v := range proxyList {
		if proxies[v].Type() == C.Pass {
			continue
		}
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
	ProxiesList = proxiesList
	GroupsList = groupsList
	if ParsingProxiesCallback != nil {
		// refresh tray menu
		go ParsingProxiesCallback(GroupsList, ProxiesList)
	}
	return proxies, providersMap, nil
}

func parseSubRules(cfg *RawConfig, proxies map[string]C.Proxy) (subRules *map[string][]C.Rule, ruleProviders map[string]providerTypes.RuleProvider, err error) {
	ruleProviders = map[string]providerTypes.RuleProvider{}
	subRules = &map[string][]C.Rule{}
	log.Infoln("Geodata Loader mode: %s", geodata.LoaderName())
	// parse rule provider
	for name, mapping := range cfg.RuleProvider {
		rp, err := RP.ParseRuleProvider(name, mapping, R.ParseRule)
		if err != nil {
			return nil, nil, err
		}

		ruleProviders[name] = rp
		RP.SetRuleProvider(rp)
	}

	for name, rawRules := range cfg.SubRules {
		var rules []C.Rule
		for idx, line := range rawRules {
			rawRule := trimArr(strings.Split(line, ","))
			var (
				payload  string
				target   string
				params   []string
				ruleName = strings.ToUpper(rawRule[0])
			)

			l := len(rawRule)

			if ruleName == "NOT" || ruleName == "OR" || ruleName == "AND" || ruleName == "SUB-RULE" {
				target = rawRule[l-1]
				payload = strings.Join(rawRule[1:l-1], ",")
			} else {
				if l < 2 {
					return nil, nil, fmt.Errorf("sub-rules[%d] [%s] error: format invalid", idx, line)
				}
				if l < 4 {
					rawRule = append(rawRule, make([]string, 4-l)...)
				}
				if ruleName == "MATCH" {
					l = 2
				}
				if l >= 3 {
					l = 3
					payload = rawRule[1]
				}
				target = rawRule[l-1]
				params = rawRule[l:]
			}

			if _, ok := proxies[target]; !ok && ruleName != "SUB-RULE" {
				return nil, nil, fmt.Errorf("sub-rules[%d:%s] [%s] error: proxy [%s] not found", idx, name, line, target)
			}

			params = trimArr(params)
			parsed, parseErr := R.ParseRule(ruleName, payload, target, params, subRules)
			if parseErr != nil {
				return nil, nil, fmt.Errorf("sub-rules[%d] [%s] error: %s", idx, line, parseErr.Error())
			}

			rules = append(rules, parsed)
		}
		(*subRules)[name] = rules
	}

	if err = verifySubRule(subRules); err != nil {
		return nil, nil, err
	}

	return
}

func verifySubRule(subRules *map[string][]C.Rule) error {
	for name := range *subRules {
		err := verifySubRuleCircularReferences(name, subRules, []string{})
		if err != nil {
			return err
		}
	}
	return nil
}

func verifySubRuleCircularReferences(n string, subRules *map[string][]C.Rule, arr []string) error {
	isInArray := func(v string, array []string) bool {
		for _, c := range array {
			if v == c {
				return true
			}
		}
		return false
	}

	arr = append(arr, n)
	for i, rule := range (*subRules)[n] {
		if rule.RuleType() == C.SubRules {
			if _, ok := (*subRules)[rule.Adapter()]; !ok {
				return fmt.Errorf("sub-rule[%d:%s] error: [%s] not found", i, n, rule.Adapter())
			}
			if isInArray(rule.Adapter(), arr) {
				arr = append(arr, rule.Adapter())
				return fmt.Errorf("sub-rule error: circular references [%s]", strings.Join(arr, "->"))
			}

			if err := verifySubRuleCircularReferences(rule.Adapter(), subRules, arr); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseRules(cfg *RawConfig, proxies map[string]C.Proxy, subRules *map[string][]C.Rule) ([]C.Rule, error) {
	var rules []C.Rule
	rulesConfig := cfg.Rule

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

		if ruleName == "NOT" || ruleName == "OR" || ruleName == "AND" || ruleName == "SUB-RULE" {
			target = rule[l-1]
			payload = strings.Join(rule[1:l-1], ",")
		} else {
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
		}
		if _, ok := proxies[target]; !ok {
			if ruleName != "SUB-RULE" {
				return nil, fmt.Errorf("rules[%d] [%s] error: proxy [%s] not found", idx, line, target)
			} else if _, ok = (*subRules)[target]; !ok {
				return nil, fmt.Errorf("rules[%d] [%s] error: sub-rule [%s] not found", idx, line, target)
			}
		}

		params = trimArr(params)
		parsed, parseErr := R.ParseRule(ruleName, payload, target, params, subRules)
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

		var addr, dnsNetType, proxyAdapter string
		params := map[string]string{}
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
			if len(u.Fragment) != 0 {
				for _, s := range strings.Split(u.Fragment, "&") {
					arr := strings.Split(s, "=")
					if len(arr) == 0 {
						continue
					} else if len(arr) == 1 {
						proxyAdapter = arr[0]
					} else if len(arr) == 2 {
						params[arr[0]] = arr[1]
					} else {
						params[arr[0]] = strings.Join(arr[1:], "=")
					}
				}
			}
		case "dhcp":
			addr = u.Host
			dnsNetType = "dhcp" // UDP from DHCP
		case "quic":
			addr, err = hostWithDefaultPort(u.Host, "853")
			dnsNetType = "quic" // DNS over QUIC
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
				ProxyAdapter: proxyAdapter,
				Interface:    dialer.DefaultInterface,
				Params:       params,
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

func parseFallbackGeoSite(countries []string, rules []C.Rule) ([]*router.DomainMatcher, error) {
	var sites []*router.DomainMatcher
	if len(countries) > 0 {
		if err := geodata.InitGeoSite(); err != nil {
			return nil, fmt.Errorf("can't initial GeoSite: %s", err)
		}
	}

	for _, country := range countries {
		found := false
		for _, rule := range rules {
			if rule.RuleType() == C.GEOSITE {
				if strings.EqualFold(country, rule.Payload()) {
					found = true
					sites = append(sites, rule.(C.RuleGeoSite).GetDomainMatcher())
					log.Infoln("Start initial GeoSite dns fallback filter from rule `%s`", country)
				}
			}
		}

		if !found {
			matcher, recordsCount, err := geodata.LoadGeoSiteMatcher(country)
			if err != nil {
				return nil, err
			}

			sites = append(sites, matcher)

			log.Infoln("Start initial GeoSite dns fallback filter `%s`, records: %d", country, recordsCount)
		}
	}
	runtime.GC()
	return sites, nil
}

func parseDNS(rawCfg *RawConfig, hosts *trie.DomainTrie[netip.Addr], rules []C.Rule) (*DNS, error) {
	cfg := rawCfg.DNS
	if cfg.Enable && len(cfg.NameServer) == 0 {
		return nil, fmt.Errorf("if DNS configuration is turned on, NameServer cannot be empty")
	}

	dnsCfg := &DNS{
		Enable:       cfg.Enable,
		Listen:       cfg.Listen,
		PreferH3:     cfg.PreferH3,
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
			u, err := url.Parse(ns.Addr)
			if err == nil && net.ParseIP(u.Host) == nil {
				if ip, _, err := net.SplitHostPort(u.Host); err != nil || net.ParseIP(ip) == nil {
					return nil, errors.New("default nameserver should be pure IP")
				}
			}
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
		fallbackGeoSite, err := parseFallbackGeoSite(cfg.FallbackFilter.GeoSite, rules)
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

func parseTun(rawTun RawTun, general *General, dnsCfg *DNS) (*Tun, error) {
	var dnsHijack []netip.AddrPort

	for _, d := range rawTun.DNSHijack {
		if _, after, ok := strings.Cut(d, "://"); ok {
			d = after
		}
		d = strings.Replace(d, "any", "0.0.0.0", 1)
		addrPort, err := netip.ParseAddrPort(d)
		if err != nil {
			return nil, fmt.Errorf("parse dns-hijack url error: %w", err)
		}

		dnsHijack = append(dnsHijack, addrPort)
	}

	var tunAddressPrefix netip.Prefix
	if dnsCfg.FakeIPRange != nil {
		tunAddressPrefix = *dnsCfg.FakeIPRange.IPNet()
	} else {
		tunAddressPrefix = netip.MustParsePrefix("198.18.0.1/16")
	}
	tunAddressPrefix = netip.PrefixFrom(tunAddressPrefix.Addr(), 30)

	return &Tun{
		Enable:              rawTun.Enable,
		Device:              rawTun.Device,
		Stack:               rawTun.Stack,
		DNSHijack:           dnsHijack,
		AutoRoute:           rawTun.AutoRoute,
		AutoDetectInterface: rawTun.AutoDetectInterface,
		RedirectToTun:       rawTun.RedirectToTun,

		MTU:                    rawTun.MTU,
		Inet4Address:           []ListenPrefix{ListenPrefix(tunAddressPrefix)},
		Inet6Address:           rawTun.Inet6Address,
		StrictRoute:            rawTun.StrictRoute,
		Inet4RouteAddress:      rawTun.Inet4RouteAddress,
		Inet6RouteAddress:      rawTun.Inet6RouteAddress,
		IncludeUID:             rawTun.IncludeUID,
		IncludeUIDRange:        rawTun.IncludeUIDRange,
		ExcludeUID:             rawTun.ExcludeUID,
		ExcludeUIDRange:        rawTun.ExcludeUIDRange,
		IncludeAndroidUser:     rawTun.IncludeAndroidUser,
		IncludePackage:         rawTun.IncludePackage,
		ExcludePackage:         rawTun.ExcludePackage,
		EndpointIndependentNat: rawTun.EndpointIndependentNat,
		UDPTimeout:             rawTun.UDPTimeout,
	}, nil
}

func parseSniffer(snifferRaw RawSniffer) (*Sniffer, error) {
	sniffer := &Sniffer{
		Enable:          snifferRaw.Enable,
		ForceDnsMapping: snifferRaw.ForceDnsMapping,
		ParsePureIp:     snifferRaw.ParsePureIp,
	}

	var ports []utils.Range[uint16]
	if len(snifferRaw.Ports) == 0 {
		ports = append(ports, *utils.NewRange[uint16](80, 80))
		ports = append(ports, *utils.NewRange[uint16](443, 443))
	} else {
		for _, portRange := range snifferRaw.Ports {
			portRaws := strings.Split(portRange, "-")
			p, err := strconv.ParseUint(portRaws[0], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("%s format error", portRange)
			}

			start := uint16(p)
			if len(portRaws) > 1 {
				p, err = strconv.ParseUint(portRaws[1], 10, 16)
				if err != nil {
					return nil, fmt.Errorf("%s format error", portRange)
				}

				end := uint16(p)
				ports = append(ports, *utils.NewRange(start, end))
			} else {
				ports = append(ports, *utils.NewRange(start, start))
			}
		}
	}

	sniffer.Ports = &ports

	loadSniffer := make(map[snifferTypes.Type]struct{})

	for _, snifferName := range snifferRaw.Sniffing {
		find := false
		for _, snifferType := range snifferTypes.List {
			if snifferType.String() == strings.ToUpper(snifferName) {
				find = true
				loadSniffer[snifferType] = struct{}{}
			}
		}

		if !find {
			return nil, fmt.Errorf("not find the sniffer[%s]", snifferName)
		}
	}

	for st := range loadSniffer {
		sniffer.Sniffers = append(sniffer.Sniffers, st)
	}
	sniffer.ForceDomain = trie.New[bool]()
	for _, domain := range snifferRaw.ForceDomain {
		err := sniffer.ForceDomain.Insert(domain, true)
		if err != nil {
			return nil, fmt.Errorf("error domian[%s] in force-domain, error:%v", domain, err)
		}
	}

	sniffer.SkipDomain = trie.New[bool]()
	for _, domain := range snifferRaw.SkipDomain {
		err := sniffer.SkipDomain.Insert(domain, true)
		if err != nil {
			return nil, fmt.Errorf("error domian[%s] in force-domain, error:%v", domain, err)
		}
	}

	return sniffer, nil
}
