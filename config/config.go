package config

import (
	"container/list"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/adapter/provider"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/auth"
	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
	P "github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/component/resolver"
	SNIFF "github.com/metacubex/mihomo/component/sniffer"
	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	providerTypes "github.com/metacubex/mihomo/constant/provider"
	snifferTypes "github.com/metacubex/mihomo/constant/sniffer"
	"github.com/metacubex/mihomo/dns"
	L "github.com/metacubex/mihomo/listener"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"
	R "github.com/metacubex/mihomo/rules"
	RP "github.com/metacubex/mihomo/rules/provider"
	T "github.com/metacubex/mihomo/tunnel"

	orderedmap "github.com/wk8/go-ordered-map/v2"
	"gopkg.in/yaml.v3"
)

// General config
type General struct {
	Inbound
	Controller
	Mode                    T.TunnelMode `json:"mode"`
	UnifiedDelay            bool
	LogLevel                log.LogLevel      `json:"log-level"`
	IPv6                    bool              `json:"ipv6"`
	Interface               string            `json:"interface-name"`
	RoutingMark             int               `json:"-"`
	GeoXUrl                 GeoXUrl           `json:"geox-url"`
	GeoAutoUpdate           bool              `json:"geo-auto-update"`
	GeoUpdateInterval       int               `json:"geo-update-interval"`
	GeodataMode             bool              `json:"geodata-mode"`
	GeodataLoader           string            `json:"geodata-loader"`
	GeositeMatcher          string            `json:"geosite-matcher"`
	TCPConcurrent           bool              `json:"tcp-concurrent"`
	FindProcessMode         P.FindProcessMode `json:"find-process-mode"`
	Sniffing                bool              `json:"sniffing"`
	EBpf                    EBpf              `json:"-"`
	GlobalClientFingerprint string            `json:"global-client-fingerprint"`
	GlobalUA                string            `json:"global-ua"`
}

// Inbound config
type Inbound struct {
	Port              int            `json:"port"`
	SocksPort         int            `json:"socks-port"`
	RedirPort         int            `json:"redir-port"`
	TProxyPort        int            `json:"tproxy-port"`
	MixedPort         int            `json:"mixed-port"`
	Tun               LC.Tun         `json:"tun"`
	TuicServer        LC.TuicServer  `json:"tuic-server"`
	ShadowSocksConfig string         `json:"ss-config"`
	VmessConfig       string         `json:"vmess-config"`
	Authentication    []string       `json:"authentication"`
	SkipAuthPrefixes  []netip.Prefix `json:"skip-auth-prefixes"`
	LanAllowedIPs     []netip.Prefix `json:"lan-allowed-ips"`
	LanDisAllowedIPs  []netip.Prefix `json:"lan-disallowed-ips"`
	AllowLan          bool           `json:"allow-lan"`
	BindAddress       string         `json:"bind-address"`
	InboundTfo        bool           `json:"inbound-tfo"`
	InboundMPTCP      bool           `json:"inbound-mptcp"`
}

// Controller config
type Controller struct {
	ExternalController     string `json:"-"`
	ExternalControllerTLS  string `json:"-"`
	ExternalControllerUnix string `json:"-"`
	ExternalUI             string `json:"-"`
	Secret                 string `json:"-"`
}

// NTP config
type NTP struct {
	Enable        bool   `yaml:"enable"`
	Server        string `yaml:"server"`
	Port          int    `yaml:"port"`
	Interval      int    `yaml:"interval"`
	DialerProxy   string `yaml:"dialer-proxy"`
	WriteToSystem bool   `yaml:"write-to-system"`
}

// DNS config
type DNS struct {
	Enable                bool             `yaml:"enable"`
	PreferH3              bool             `yaml:"prefer-h3"`
	IPv6                  bool             `yaml:"ipv6"`
	IPv6Timeout           uint             `yaml:"ipv6-timeout"`
	NameServer            []dns.NameServer `yaml:"nameserver"`
	Fallback              []dns.NameServer `yaml:"fallback"`
	FallbackFilter        FallbackFilter   `yaml:"fallback-filter"`
	Listen                string           `yaml:"listen"`
	EnhancedMode          C.DNSMode        `yaml:"enhanced-mode"`
	DefaultNameserver     []dns.NameServer `yaml:"default-nameserver"`
	CacheAlgorithm        string           `yaml:"cache-algorithm"`
	FakeIPRange           *fakeip.Pool
	Hosts                 *trie.DomainTrie[resolver.HostValue]
	NameServerPolicy      *orderedmap.OrderedMap[string, []dns.NameServer]
	ProxyServerNameserver []dns.NameServer
}

// FallbackFilter config
type FallbackFilter struct {
	GeoIP     bool                   `yaml:"geoip"`
	GeoIPCode string                 `yaml:"geoip-code"`
	IPCIDR    []netip.Prefix         `yaml:"ipcidr"`
	Domain    []string               `yaml:"domain"`
	GeoSite   []router.DomainMatcher `yaml:"geosite"`
}

// Profile config
type Profile struct {
	StoreSelected bool `yaml:"store-selected"`
	StoreFakeIP   bool `yaml:"store-fake-ip"`
}

type TLS struct {
	Certificate     string   `yaml:"certificate"`
	PrivateKey      string   `yaml:"private-key"`
	CustomTrustCert []string `yaml:"custom-certifactes"`
}

// IPTables config
type IPTables struct {
	Enable           bool     `yaml:"enable" json:"enable"`
	InboundInterface string   `yaml:"inbound-interface" json:"inbound-interface"`
	Bypass           []string `yaml:"bypass" json:"bypass"`
	DnsRedirect      bool     `yaml:"dns-redirect" json:"dns-redirect"`
}

type Sniffer struct {
	Enable          bool
	Sniffers        map[snifferTypes.Type]SNIFF.SnifferConfig
	ForceDomain     *trie.DomainSet
	SkipDomain      *trie.DomainSet
	ForceDnsMapping bool
	ParsePureIp     bool
}

// Experimental config
type Experimental struct {
	Fingerprints     []string `yaml:"fingerprints"`
	QUICGoDisableGSO bool     `yaml:"quic-go-disable-gso"`
	QUICGoDisableECN bool     `yaml:"quic-go-disable-ecn"`
	IP4PEnable       bool     `yaml:"dialer-ip4p-convert"`
}

// Config is mihomo config manager
type Config struct {
	General       *General
	IPTables      *IPTables
	NTP           *NTP
	DNS           *DNS
	Experimental  *Experimental
	Hosts         *trie.DomainTrie[resolver.HostValue]
	Profile       *Profile
	Rules         []C.Rule
	SubRules      map[string][]C.Rule
	Users         []auth.AuthUser
	Proxies       map[string]C.Proxy
	Listeners     map[string]C.InboundListener
	Providers     map[string]providerTypes.ProxyProvider
	RuleProviders map[string]providerTypes.RuleProvider
	Tunnels       []LC.Tunnel
	Sniffer       *Sniffer
	TLS           *TLS
}

type RawNTP struct {
	Enable        bool   `yaml:"enable"`
	Server        string `yaml:"server"`
	ServerPort    int    `yaml:"server-port"`
	Interval      int    `yaml:"interval"`
	DialerProxy   string `yaml:"dialer-proxy"`
	WriteToSystem bool   `yaml:"write-to-system"`
}

type RawDNS struct {
	Enable                bool                                `yaml:"enable" json:"enable"`
	PreferH3              bool                                `yaml:"prefer-h3" json:"prefer-h3"`
	IPv6                  bool                                `yaml:"ipv6" json:"ipv6"`
	IPv6Timeout           uint                                `yaml:"ipv6-timeout" json:"ipv6-timeout"`
	UseHosts              bool                                `yaml:"use-hosts" json:"use-hosts"`
	NameServer            []string                            `yaml:"nameserver" json:"nameserver"`
	Fallback              []string                            `yaml:"fallback" json:"fallback"`
	FallbackFilter        RawFallbackFilter                   `yaml:"fallback-filter" json:"fallback-filter"`
	Listen                string                              `yaml:"listen" json:"listen"`
	EnhancedMode          C.DNSMode                           `yaml:"enhanced-mode" json:"enhanced-mode"`
	FakeIPRange           string                              `yaml:"fake-ip-range" json:"fake-ip-range"`
	FakeIPFilter          []string                            `yaml:"fake-ip-filter" json:"fake-ip-filter"`
	DefaultNameserver     []string                            `yaml:"default-nameserver" json:"default-nameserver"`
	CacheAlgorithm        string                              `yaml:"cache-algorithm" json:"cache-algorithm"`
	NameServerPolicy      *orderedmap.OrderedMap[string, any] `yaml:"nameserver-policy" json:"nameserver-policy"`
	ProxyServerNameserver []string                            `yaml:"proxy-server-nameserver" json:"proxy-server-nameserver"`
}

type RawFallbackFilter struct {
	GeoIP     bool     `yaml:"geoip" json:"geoip"`
	GeoIPCode string   `yaml:"geoip-code" json:"geoip-code"`
	IPCIDR    []string `yaml:"ipcidr" json:"ipcidr"`
	Domain    []string `yaml:"domain" json:"domain"`
	GeoSite   []string `yaml:"geosite" json:"geosite"`
}

type RawClashForAndroid struct {
	AppendSystemDNS   bool   `yaml:"append-system-dns" json:"append-system-dns"`
	UiSubtitlePattern string `yaml:"ui-subtitle-pattern" json:"ui-subtitle-pattern"`
}

type RawTun struct {
	Enable              bool       `yaml:"enable" json:"enable"`
	Device              string     `yaml:"device" json:"device"`
	Stack               C.TUNStack `yaml:"stack" json:"stack"`
	DNSHijack           []string   `yaml:"dns-hijack" json:"dns-hijack"`
	AutoRoute           bool       `yaml:"auto-route" json:"auto-route"`
	AutoDetectInterface bool       `yaml:"auto-detect-interface"`
	RedirectToTun       []string   `yaml:"-" json:"-"`

	MTU        uint32 `yaml:"mtu" json:"mtu,omitempty"`
	GSO        bool   `yaml:"gso" json:"gso,omitempty"`
	GSOMaxSize uint32 `yaml:"gso-max-size" json:"gso-max-size,omitempty"`
	//Inet4Address           []netip.Prefix `yaml:"inet4-address" json:"inet4_address,omitempty"`
	Inet6Address             []netip.Prefix `yaml:"inet6-address" json:"inet6_address,omitempty"`
	StrictRoute              bool           `yaml:"strict-route" json:"strict_route,omitempty"`
	Inet4RouteAddress        []netip.Prefix `yaml:"inet4-route-address" json:"inet4_route_address,omitempty"`
	Inet6RouteAddress        []netip.Prefix `yaml:"inet6-route-address" json:"inet6_route_address,omitempty"`
	Inet4RouteExcludeAddress []netip.Prefix `yaml:"inet4-route-exclude-address" json:"inet4_route_exclude_address,omitempty"`
	Inet6RouteExcludeAddress []netip.Prefix `yaml:"inet6-route-exclude-address" json:"inet6_route_exclude_address,omitempty"`
	IncludeInterface         []string       `yaml:"include-interface" json:"include-interface,omitempty"`
	ExcludeInterface         []string       `yaml:"exclude-interface" json:"exclude-interface,omitempty"`
	IncludeUID               []uint32       `yaml:"include-uid" json:"include_uid,omitempty"`
	IncludeUIDRange          []string       `yaml:"include-uid-range" json:"include_uid_range,omitempty"`
	ExcludeUID               []uint32       `yaml:"exclude-uid" json:"exclude_uid,omitempty"`
	ExcludeUIDRange          []string       `yaml:"exclude-uid-range" json:"exclude_uid_range,omitempty"`
	IncludeAndroidUser       []int          `yaml:"include-android-user" json:"include_android_user,omitempty"`
	IncludePackage           []string       `yaml:"include-package" json:"include_package,omitempty"`
	ExcludePackage           []string       `yaml:"exclude-package" json:"exclude_package,omitempty"`
	EndpointIndependentNat   bool           `yaml:"endpoint-independent-nat" json:"endpoint_independent_nat,omitempty"`
	UDPTimeout               int64          `yaml:"udp-timeout" json:"udp_timeout,omitempty"`
	FileDescriptor           int            `yaml:"file-descriptor" json:"file-descriptor"`
	TableIndex               int            `yaml:"table-index" json:"table-index"`
}

type RawTuicServer struct {
	Enable                bool              `yaml:"enable" json:"enable"`
	Listen                string            `yaml:"listen" json:"listen"`
	Token                 []string          `yaml:"token" json:"token"`
	Users                 map[string]string `yaml:"users" json:"users,omitempty"`
	Certificate           string            `yaml:"certificate" json:"certificate"`
	PrivateKey            string            `yaml:"private-key" json:"private-key"`
	CongestionController  string            `yaml:"congestion-controller" json:"congestion-controller,omitempty"`
	MaxIdleTime           int               `yaml:"max-idle-time" json:"max-idle-time,omitempty"`
	AuthenticationTimeout int               `yaml:"authentication-timeout" json:"authentication-timeout,omitempty"`
	ALPN                  []string          `yaml:"alpn" json:"alpn,omitempty"`
	MaxUdpRelayPacketSize int               `yaml:"max-udp-relay-packet-size" json:"max-udp-relay-packet-size,omitempty"`
	CWND                  int               `yaml:"cwnd" json:"cwnd,omitempty"`
}

type RawConfig struct {
	Port                    int               `yaml:"port" json:"port"`
	SocksPort               int               `yaml:"socks-port" json:"socks-port"`
	RedirPort               int               `yaml:"redir-port" json:"redir-port"`
	TProxyPort              int               `yaml:"tproxy-port" json:"tproxy-port"`
	MixedPort               int               `yaml:"mixed-port" json:"mixed-port"`
	ShadowSocksConfig       string            `yaml:"ss-config"`
	VmessConfig             string            `yaml:"vmess-config"`
	InboundTfo              bool              `yaml:"inbound-tfo"`
	InboundMPTCP            bool              `yaml:"inbound-mptcp"`
	Authentication          []string          `yaml:"authentication" json:"authentication"`
	SkipAuthPrefixes        []netip.Prefix    `yaml:"skip-auth-prefixes"`
	LanAllowedIPs           []netip.Prefix    `yaml:"lan-allowed-ips"`
	LanDisAllowedIPs        []netip.Prefix    `yaml:"lan-disallowed-ips"`
	AllowLan                bool              `yaml:"allow-lan" json:"allow-lan"`
	BindAddress             string            `yaml:"bind-address" json:"bind-address"`
	Mode                    T.TunnelMode      `yaml:"mode" json:"mode"`
	UnifiedDelay            bool              `yaml:"unified-delay" json:"unified-delay"`
	LogLevel                log.LogLevel      `yaml:"log-level" json:"log-level"`
	IPv6                    bool              `yaml:"ipv6" json:"ipv6"`
	ExternalController      string            `yaml:"external-controller"`
	ExternalControllerUnix  string            `yaml:"external-controller-unix"`
	ExternalControllerTLS   string            `yaml:"external-controller-tls"`
	ExternalUI              string            `yaml:"external-ui"`
	ExternalUIURL           string            `yaml:"external-ui-url" json:"external-ui-url"`
	ExternalUIName          string            `yaml:"external-ui-name" json:"external-ui-name"`
	Secret                  string            `yaml:"secret"`
	Interface               string            `yaml:"interface-name"`
	RoutingMark             int               `yaml:"routing-mark"`
	Tunnels                 []LC.Tunnel       `yaml:"tunnels"`
	GeoAutoUpdate           bool              `yaml:"geo-auto-update" json:"geo-auto-update"`
	GeoUpdateInterval       int               `yaml:"geo-update-interval" json:"geo-update-interval"`
	GeodataMode             bool              `yaml:"geodata-mode" json:"geodata-mode"`
	GeodataLoader           string            `yaml:"geodata-loader" json:"geodata-loader"`
	GeositeMatcher          string            `yaml:"geosite-matcher" json:"geosite-matcher"`
	TCPConcurrent           bool              `yaml:"tcp-concurrent" json:"tcp-concurrent"`
	FindProcessMode         P.FindProcessMode `yaml:"find-process-mode" json:"find-process-mode"`
	GlobalClientFingerprint string            `yaml:"global-client-fingerprint"`
	GlobalUA                string            `yaml:"global-ua"`
	KeepAliveInterval       int               `yaml:"keep-alive-interval"`

	Sniffer       RawSniffer                `yaml:"sniffer" json:"sniffer"`
	ProxyProvider map[string]map[string]any `yaml:"proxy-providers"`
	RuleProvider  map[string]map[string]any `yaml:"rule-providers"`
	Hosts         map[string]any            `yaml:"hosts" json:"hosts"`
	NTP           RawNTP                    `yaml:"ntp" json:"ntp"`
	DNS           RawDNS                    `yaml:"dns" json:"dns"`
	Tun           RawTun                    `yaml:"tun"`
	TuicServer    RawTuicServer             `yaml:"tuic-server"`
	EBpf          EBpf                      `yaml:"ebpf"`
	IPTables      IPTables                  `yaml:"iptables"`
	Experimental  Experimental              `yaml:"experimental"`
	Profile       Profile                   `yaml:"profile"`
	GeoXUrl       GeoXUrl                   `yaml:"geox-url"`
	Proxy         []map[string]any          `yaml:"proxies"`
	ProxyGroup    []map[string]any          `yaml:"proxy-groups"`
	Rule          []string                  `yaml:"rules"`
	SubRules      map[string][]string       `yaml:"sub-rules"`
	RawTLS        TLS                       `yaml:"tls"`
	Listeners     []map[string]any          `yaml:"listeners"`

	ClashForAndroid RawClashForAndroid `yaml:"clash-for-android" json:"clash-for-android"`
}

type GeoXUrl struct {
	GeoIp   string `yaml:"geoip" json:"geoip"`
	Mmdb    string `yaml:"mmdb" json:"mmdb"`
	ASN     string `yaml:"asn" json:"asn"`
	GeoSite string `yaml:"geosite" json:"geosite"`
}

type RawSniffer struct {
	Enable          bool                         `yaml:"enable" json:"enable"`
	OverrideDest    bool                         `yaml:"override-destination" json:"override-destination"`
	Sniffing        []string                     `yaml:"sniffing" json:"sniffing"`
	ForceDomain     []string                     `yaml:"force-domain" json:"force-domain"`
	SkipDomain      []string                     `yaml:"skip-domain" json:"skip-domain"`
	Ports           []string                     `yaml:"port-whitelist" json:"port-whitelist"`
	ForceDnsMapping bool                         `yaml:"force-dns-mapping" json:"force-dns-mapping"`
	ParsePureIp     bool                         `yaml:"parse-pure-ip" json:"parse-pure-ip"`
	Sniff           map[string]RawSniffingConfig `yaml:"sniff" json:"sniff"`
}

type RawSniffingConfig struct {
	Ports        []string `yaml:"ports" json:"ports"`
	OverrideDest *bool    `yaml:"override-destination" json:"override-destination"`
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
		AllowLan:          false,
		BindAddress:       "*",
		LanAllowedIPs:     []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		IPv6:              true,
		Mode:              T.Rule,
		GeoAutoUpdate:     false,
		GeoUpdateInterval: 24,
		GeodataMode:       C.GeodataMode,
		GeodataLoader:     "memconservative",
		UnifiedDelay:      false,
		Authentication:    []string{},
		LogLevel:          log.INFO,
		Hosts:             map[string]any{},
		Rule:              []string{},
		Proxy:             []map[string]any{},
		ProxyGroup:        []map[string]any{},
		TCPConcurrent:     false,
		FindProcessMode:   P.FindProcessStrict,
		GlobalUA:          "clash.meta/" + C.Version,
		Tun: RawTun{
			Enable:              false,
			Device:              "",
			Stack:               C.TunGvisor,
			DNSHijack:           []string{"0.0.0.0:53"}, // default hijack all dns query
			AutoRoute:           true,
			AutoDetectInterface: true,
			Inet6Address:        []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
		},
		TuicServer: RawTuicServer{
			Enable:                false,
			Token:                 nil,
			Users:                 nil,
			Certificate:           "",
			PrivateKey:            "",
			Listen:                "",
			CongestionController:  "",
			MaxIdleTime:           15000,
			AuthenticationTimeout: 1000,
			ALPN:                  []string{"h3"},
			MaxUdpRelayPacketSize: 1500,
		},
		EBpf: EBpf{
			RedirectToTun: []string{},
			AutoRedir:     []string{},
		},
		IPTables: IPTables{
			Enable:           false,
			InboundInterface: "lo",
			Bypass:           []string{},
			DnsRedirect:      true,
		},
		NTP: RawNTP{
			Enable:        false,
			WriteToSystem: false,
			Server:        "time.apple.com",
			ServerPort:    123,
			Interval:      30,
		},
		DNS: RawDNS{
			Enable:       false,
			IPv6:         false,
			UseHosts:     true,
			IPv6Timeout:  100,
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
		Experimental: Experimental{
			// https://github.com/quic-go/quic-go/issues/4178
			// Quic-go currently cannot automatically fall back on platforms that do not support ecn, so this feature is turned off by default.
			QUICGoDisableECN: true,
		},
		Sniffer: RawSniffer{
			Enable:          false,
			Sniffing:        []string{},
			ForceDomain:     []string{},
			SkipDomain:      []string{},
			Ports:           []string{},
			ForceDnsMapping: true,
			ParsePureIp:     true,
			OverrideDest:    true,
		},
		Profile: Profile{
			StoreSelected: true,
		},
		GeoXUrl: GeoXUrl{
			Mmdb:    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb",
			ASN:     "https://github.com/xishang0128/geoip/releases/download/latest/GeoLite2-ASN.mmdb",
			GeoIp:   "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat",
			GeoSite: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
		},
		ExternalUIURL: "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
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
	config.TLS = &rawCfg.RawTLS

	general, err := parseGeneral(rawCfg)
	if err != nil {
		return nil, err
	}
	config.General = general

	if len(config.General.GlobalClientFingerprint) != 0 {
		log.Debugln("GlobalClientFingerprint: %s", config.General.GlobalClientFingerprint)
		tlsC.SetGlobalUtlsClient(config.General.GlobalClientFingerprint)
	}

	proxies, providers, err := parseProxies(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Proxies = proxies
	config.Providers = providers

	listener, err := parseListeners(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Listeners = listener

	log.Infoln("Geodata Loader mode: %s", geodata.LoaderName())
	log.Infoln("Geosite Matcher implementation: %s", geodata.SiteMatcherName())
	ruleProviders, err := parseRuleProviders(rawCfg)
	if err != nil {
		return nil, err
	}
	config.RuleProviders = ruleProviders

	subRules, err := parseSubRules(rawCfg, proxies)
	if err != nil {
		return nil, err
	}
	config.SubRules = subRules

	rules, err := parseRules(rawCfg.Rule, proxies, subRules, "rules")
	if err != nil {
		return nil, err
	}
	config.Rules = rules

	hosts, err := parseHosts(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Hosts = hosts

	ntpCfg := paresNTP(rawCfg)
	config.NTP = ntpCfg

	dnsCfg, err := parseDNS(rawCfg, hosts, rules, ruleProviders)
	if err != nil {
		return nil, err
	}
	config.DNS = dnsCfg

	err = parseTun(rawCfg.Tun, config.General)
	if !features.CMFA && err != nil {
		return nil, err
	}

	err = parseTuicServer(rawCfg.TuicServer, config.General)
	if err != nil {
		return nil, err
	}

	config.Users = parseAuthentication(rawCfg.Authentication)

	config.Tunnels = rawCfg.Tunnels
	// verify tunnels
	for _, t := range config.Tunnels {
		if len(t.Proxy) > 0 {
			if _, ok := config.Proxies[t.Proxy]; !ok {
				return nil, fmt.Errorf("tunnel proxy %s not found", t.Proxy)
			}
		}
	}

	config.Sniffer, err = parseSniffer(rawCfg.Sniffer)
	if err != nil {
		return nil, err
	}

	elapsedTime := time.Since(startTime) / time.Millisecond                     // duration in ms
	log.Infoln("Initial configuration complete, total time: %dms", elapsedTime) //Segment finished in xxm

	return config, nil
}

func parseGeneral(cfg *RawConfig) (*General, error) {
	geodata.SetGeodataMode(cfg.GeodataMode)
	geodata.SetGeoAutoUpdate(cfg.GeoAutoUpdate)
	geodata.SetGeoUpdateInterval(cfg.GeoUpdateInterval)
	geodata.SetLoader(cfg.GeodataLoader)
	geodata.SetSiteMatcher(cfg.GeositeMatcher)
	C.GeoAutoUpdate = cfg.GeoAutoUpdate
	C.GeoUpdateInterval = cfg.GeoUpdateInterval
	C.GeoIpUrl = cfg.GeoXUrl.GeoIp
	C.GeoSiteUrl = cfg.GeoXUrl.GeoSite
	C.MmdbUrl = cfg.GeoXUrl.Mmdb
	C.ASNUrl = cfg.GeoXUrl.ASN
	C.GeodataMode = cfg.GeodataMode
	C.UA = cfg.GlobalUA
	if cfg.KeepAliveInterval != 0 {
		N.KeepAliveInterval = time.Duration(cfg.KeepAliveInterval) * time.Second
	}

	ExternalUIPath = cfg.ExternalUI
	// checkout externalUI exist
	if ExternalUIPath != "" {
		ExternalUIPath = C.Path.Resolve(ExternalUIPath)
		if _, err := os.Stat(ExternalUIPath); os.IsNotExist(err) {
			defaultUIpath := path.Join(C.Path.HomeDir(), "ui")
			log.Warnln("external-ui: %s does not exist, creating folder in %s", ExternalUIPath, defaultUIpath)
			if err := os.MkdirAll(defaultUIpath, os.ModePerm); err != nil {
				return nil, err
			}
			ExternalUIPath = defaultUIpath
			cfg.ExternalUI = defaultUIpath
		}
	}
	// checkout UIpath/name exist
	if cfg.ExternalUIName != "" {
		ExternalUIName = cfg.ExternalUIName
	} else {
		ExternalUIFolder = ExternalUIPath
	}
	if cfg.ExternalUIURL != "" {
		ExternalUIURL = cfg.ExternalUIURL
	}

	cfg.Tun.RedirectToTun = cfg.EBpf.RedirectToTun
	return &General{
		Inbound: Inbound{
			Port:              cfg.Port,
			SocksPort:         cfg.SocksPort,
			RedirPort:         cfg.RedirPort,
			TProxyPort:        cfg.TProxyPort,
			MixedPort:         cfg.MixedPort,
			ShadowSocksConfig: cfg.ShadowSocksConfig,
			VmessConfig:       cfg.VmessConfig,
			AllowLan:          cfg.AllowLan,
			SkipAuthPrefixes:  cfg.SkipAuthPrefixes,
			LanAllowedIPs:     cfg.LanAllowedIPs,
			LanDisAllowedIPs:  cfg.LanDisAllowedIPs,
			BindAddress:       cfg.BindAddress,
			InboundTfo:        cfg.InboundTfo,
			InboundMPTCP:      cfg.InboundMPTCP,
		},
		Controller: Controller{
			ExternalController:     cfg.ExternalController,
			ExternalUI:             cfg.ExternalUI,
			Secret:                 cfg.Secret,
			ExternalControllerUnix: cfg.ExternalControllerUnix,
			ExternalControllerTLS:  cfg.ExternalControllerTLS,
		},
		UnifiedDelay:            cfg.UnifiedDelay,
		Mode:                    cfg.Mode,
		LogLevel:                cfg.LogLevel,
		IPv6:                    cfg.IPv6,
		Interface:               cfg.Interface,
		RoutingMark:             cfg.RoutingMark,
		GeoXUrl:                 cfg.GeoXUrl,
		GeoAutoUpdate:           cfg.GeoAutoUpdate,
		GeoUpdateInterval:       cfg.GeoUpdateInterval,
		GeodataMode:             cfg.GeodataMode,
		GeodataLoader:           cfg.GeodataLoader,
		TCPConcurrent:           cfg.TCPConcurrent,
		FindProcessMode:         cfg.FindProcessMode,
		EBpf:                    cfg.EBpf,
		GlobalClientFingerprint: cfg.GlobalClientFingerprint,
		GlobalUA:                cfg.GlobalUA,
	}, nil
}

func parseProxies(cfg *RawConfig) (proxies map[string]C.Proxy, providersMap map[string]providerTypes.ProxyProvider, err error) {
	proxies = make(map[string]C.Proxy)
	providersMap = make(map[string]providerTypes.ProxyProvider)
	proxiesConfig := cfg.Proxy
	groupsConfig := cfg.ProxyGroup
	providersConfig := cfg.ProxyProvider

	var proxyList []string
	var AllProxies []string
	proxiesList := list.New()
	groupsList := list.New()

	proxies["DIRECT"] = adapter.NewProxy(outbound.NewDirect())
	proxies["REJECT"] = adapter.NewProxy(outbound.NewReject())
	proxies["REJECT-DROP"] = adapter.NewProxy(outbound.NewRejectDrop())
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
		AllProxies = append(AllProxies, proxy.Name())
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

	var AllProviders []string
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
		AllProviders = append(AllProviders, name)
	}

	// parse proxy group
	for idx, mapping := range groupsConfig {
		group, err := outboundgroup.ParseProxyGroup(mapping, proxies, providersMap, AllProxies, AllProviders)
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
	hc := provider.NewHealthCheck(ps, "", 5000, 0, true, nil)
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

func parseListeners(cfg *RawConfig) (listeners map[string]C.InboundListener, err error) {
	listeners = make(map[string]C.InboundListener)
	for index, mapping := range cfg.Listeners {
		listener, err := L.ParseListener(mapping)
		if err != nil {
			return nil, fmt.Errorf("proxy %d: %w", index, err)
		}

		if _, exist := mapping[listener.Name()]; exist {
			return nil, fmt.Errorf("listener %s is the duplicate name", listener.Name())
		}

		listeners[listener.Name()] = listener

	}
	return
}

func parseRuleProviders(cfg *RawConfig) (ruleProviders map[string]providerTypes.RuleProvider, err error) {
	ruleProviders = map[string]providerTypes.RuleProvider{}
	// parse rule provider
	for name, mapping := range cfg.RuleProvider {
		rp, err := RP.ParseRuleProvider(name, mapping, R.ParseRule)
		if err != nil {
			return nil, err
		}

		ruleProviders[name] = rp
		RP.SetRuleProvider(rp)
	}
	return
}

func parseSubRules(cfg *RawConfig, proxies map[string]C.Proxy) (subRules map[string][]C.Rule, err error) {
	subRules = map[string][]C.Rule{}
	for name := range cfg.SubRules {
		subRules[name] = make([]C.Rule, 0)
	}
	for name, rawRules := range cfg.SubRules {
		if len(name) == 0 {
			return nil, fmt.Errorf("sub-rule name is empty")
		}
		var rules []C.Rule
		rules, err = parseRules(rawRules, proxies, subRules, fmt.Sprintf("sub-rules[%s]", name))
		if err != nil {
			return nil, err
		}
		subRules[name] = rules
	}

	if err = verifySubRule(subRules); err != nil {
		return nil, err
	}

	return
}

func verifySubRule(subRules map[string][]C.Rule) error {
	for name := range subRules {
		err := verifySubRuleCircularReferences(name, subRules, []string{})
		if err != nil {
			return err
		}
	}
	return nil
}

func verifySubRuleCircularReferences(n string, subRules map[string][]C.Rule, arr []string) error {
	isInArray := func(v string, array []string) bool {
		for _, c := range array {
			if v == c {
				return true
			}
		}
		return false
	}

	arr = append(arr, n)
	for i, rule := range subRules[n] {
		if rule.RuleType() == C.SubRules {
			if _, ok := subRules[rule.Adapter()]; !ok {
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

func parseRules(rulesConfig []string, proxies map[string]C.Proxy, subRules map[string][]C.Rule, format string) ([]C.Rule, error) {
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

		if ruleName == "NOT" || ruleName == "OR" || ruleName == "AND" || ruleName == "SUB-RULE" || ruleName == "DOMAIN-REGEX" {
			target = rule[l-1]
			payload = strings.Join(rule[1:l-1], ",")
		} else {
			if l < 2 {
				return nil, fmt.Errorf("%s[%d] [%s] error: format invalid", format, idx, line)
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
				return nil, fmt.Errorf("%s[%d] [%s] error: proxy [%s] not found", format, idx, line, target)
			} else if _, ok = subRules[target]; !ok {
				return nil, fmt.Errorf("%s[%d] [%s] error: sub-rule [%s] not found", format, idx, line, target)
			}
		}

		params = trimArr(params)
		parsed, parseErr := R.ParseRule(ruleName, payload, target, params, subRules)
		if parseErr != nil {
			return nil, fmt.Errorf("%s[%d] [%s] error: %s", format, idx, line, parseErr.Error())
		}

		rules = append(rules, parsed)
	}

	return rules, nil
}

func parseHosts(cfg *RawConfig) (*trie.DomainTrie[resolver.HostValue], error) {
	tree := trie.New[resolver.HostValue]()

	// add default hosts
	hostValue, _ := resolver.NewHostValueByIPs(
		[]netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})})
	if err := tree.Insert("localhost", hostValue); err != nil {
		log.Errorln("insert localhost to host error: %s", err.Error())
	}

	if len(cfg.Hosts) != 0 {
		for domain, anyValue := range cfg.Hosts {
			if str, ok := anyValue.(string); ok && str == "lan" {
				if addrs, err := net.InterfaceAddrs(); err != nil {
					log.Errorln("insert lan to host error: %s", err)
				} else {
					ips := make([]netip.Addr, 0)
					for _, addr := range addrs {
						if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && !ipnet.IP.IsLinkLocalUnicast() {
							if ip, err := netip.ParseAddr(ipnet.IP.String()); err == nil {
								ips = append(ips, ip)
							}
						}
					}
					anyValue = ips
				}
			}
			value, err := resolver.NewHostValue(anyValue)
			if err != nil {
				return nil, fmt.Errorf("%s is not a valid value", anyValue)
			}
			if value.IsDomain {
				node := tree.Search(value.Domain)
				for node != nil && node.Data().IsDomain {
					if node.Data().Domain == domain {
						return nil, fmt.Errorf("%s, there is a cycle in domain name mapping", domain)
					}
					node = tree.Search(node.Data().Domain)
				}
			}
			_ = tree.Insert(domain, value)
		}
	}
	tree.Optimize()

	return tree, nil
}

func hostWithDefaultPort(host string, defPort string) (string, error) {
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		if !strings.Contains(err.Error(), "missing port in address") {
			return "", err
		}
		host = host + ":" + defPort
		if hostname, port, err = net.SplitHostPort(host); err != nil {
			return "", err
		}
	}

	return net.JoinHostPort(hostname, port), nil
}

func parseNameServer(servers []string, preferH3 bool) ([]dns.NameServer, error) {
	var nameservers []dns.NameServer

	for idx, server := range servers {
		server = parsePureDNSServer(server)
		u, err := url.Parse(server)
		if err != nil {
			return nil, fmt.Errorf("DNS NameServer[%d] format error: %s", idx, err.Error())
		}

		proxyName := u.Fragment

		var addr, dnsNetType string
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
			addr, err = hostWithDefaultPort(u.Host, "443")
			if err == nil {
				proxyName = ""
				clearURL := url.URL{Scheme: "https", Host: addr, Path: u.Path, User: u.User}
				addr = clearURL.String()
				dnsNetType = "https" // DNS over HTTPS
				if len(u.Fragment) != 0 {
					for _, s := range strings.Split(u.Fragment, "&") {
						arr := strings.Split(s, "=")
						if len(arr) == 0 {
							continue
						} else if len(arr) == 1 {
							proxyName = arr[0]
						} else if len(arr) == 2 {
							params[arr[0]] = arr[1]
						} else {
							params[arr[0]] = strings.Join(arr[1:], "=")
						}
					}
				}
			}
		case "dhcp":
			addr = u.Host
			dnsNetType = "dhcp" // UDP from DHCP
		case "quic":
			addr, err = hostWithDefaultPort(u.Host, "853")
			dnsNetType = "quic" // DNS over QUIC
		case "system":
			dnsNetType = "system" // System DNS
		case "rcode":
			dnsNetType = "rcode"
			addr = u.Host
			switch addr {
			case "success",
				"format_error",
				"server_failure",
				"name_error",
				"not_implemented",
				"refused":
			default:
				err = fmt.Errorf("unsupported RCode type: %s", addr)
			}
		default:
			return nil, fmt.Errorf("DNS NameServer[%d] unsupport scheme: %s", idx, u.Scheme)
		}

		if err != nil {
			return nil, fmt.Errorf("DNS NameServer[%d] format error: %s", idx, err.Error())
		}

		nameservers = append(
			nameservers,
			dns.NameServer{
				Net:       dnsNetType,
				Addr:      addr,
				ProxyName: proxyName,
				Params:    params,
				PreferH3:  preferH3,
			},
		)
	}
	return nameservers, nil
}

func init() {
	dns.ParseNameServer = func(servers []string) ([]dns.NameServer, error) { // using by wireguard
		return parseNameServer(servers, false)
	}
}

func parsePureDNSServer(server string) string {
	addPre := func(server string) string {
		return "udp://" + server
	}

	if server == "system" {
		return "system://"
	}

	if ip, err := netip.ParseAddr(server); err != nil {
		if strings.Contains(server, "://") {
			return server
		}
		return addPre(server)
	} else {
		if ip.Is4() {
			return addPre(server)
		} else {
			return addPre("[" + server + "]")
		}
	}
}
func parseNameServerPolicy(nsPolicy *orderedmap.OrderedMap[string, any], ruleProviders map[string]providerTypes.RuleProvider, preferH3 bool) (*orderedmap.OrderedMap[string, []dns.NameServer], error) {
	policy := orderedmap.New[string, []dns.NameServer]()
	updatedPolicy := orderedmap.New[string, any]()
	re := regexp.MustCompile(`[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(\.[a-zA-Z]{2,})?`)

	for pair := nsPolicy.Oldest(); pair != nil; pair = pair.Next() {
		k, v := pair.Key, pair.Value
		if strings.Contains(strings.ToLower(k), ",") {
			if strings.Contains(k, "geosite:") {
				subkeys := strings.Split(k, ":")
				subkeys = subkeys[1:]
				subkeys = strings.Split(subkeys[0], ",")
				for _, subkey := range subkeys {
					newKey := "geosite:" + subkey
					updatedPolicy.Store(newKey, v)
				}
			} else if strings.Contains(strings.ToLower(k), "rule-set:") {
				subkeys := strings.Split(k, ":")
				subkeys = subkeys[1:]
				subkeys = strings.Split(subkeys[0], ",")
				for _, subkey := range subkeys {
					newKey := "rule-set:" + subkey
					updatedPolicy.Store(newKey, v)
				}
			} else if re.MatchString(k) {
				subkeys := strings.Split(k, ",")
				for _, subkey := range subkeys {
					updatedPolicy.Store(subkey, v)
				}
			}
		} else {
			if strings.Contains(strings.ToLower(k), "geosite:") {
				updatedPolicy.Store("geosite:"+k[8:], v)
			} else if strings.Contains(strings.ToLower(k), "rule-set:") {
				updatedPolicy.Store("rule-set:"+k[9:], v)
			}
			updatedPolicy.Store(k, v)
		}
	}

	for pair := updatedPolicy.Oldest(); pair != nil; pair = pair.Next() {
		domain, server := pair.Key, pair.Value
		servers, err := utils.ToStringSlice(server)
		if err != nil {
			return nil, err
		}
		nameservers, err := parseNameServer(servers, preferH3)
		if err != nil {
			return nil, err
		}
		if _, valid := trie.ValidAndSplitDomain(domain); !valid {
			return nil, fmt.Errorf("DNS ResoverRule invalid domain: %s", domain)
		}
		if strings.HasPrefix(domain, "rule-set:") {
			domainSetName := domain[9:]
			if provider, ok := ruleProviders[domainSetName]; !ok {
				return nil, fmt.Errorf("not found rule-set: %s", domainSetName)
			} else {
				switch provider.Behavior() {
				case providerTypes.IPCIDR:
					return nil, fmt.Errorf("rule provider type error, except domain,actual %s", provider.Behavior())
				case providerTypes.Classical:
					log.Warnln("%s provider is %s, only matching it contain domain rule", provider.Name(), provider.Behavior())
				}
			}
		}
		policy.Store(domain, nameservers)
	}

	return policy, nil
}

func parseFallbackIPCIDR(ips []string) ([]netip.Prefix, error) {
	var ipNets []netip.Prefix

	for idx, ip := range ips {
		ipnet, err := netip.ParsePrefix(ip)
		if err != nil {
			return nil, fmt.Errorf("DNS FallbackIP[%d] format error: %s", idx, err.Error())
		}
		ipNets = append(ipNets, ipnet)
	}

	return ipNets, nil
}

func parseFallbackGeoSite(countries []string, rules []C.Rule) ([]router.DomainMatcher, error) {
	var sites []router.DomainMatcher
	if len(countries) > 0 {
		if err := geodata.InitGeoSite(); err != nil {
			return nil, fmt.Errorf("can't initial GeoSite: %s", err)
		}
		log.Warnln("replace fallback-filter.geosite with nameserver-policy, it will be removed in the future")
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
	return sites, nil
}

func paresNTP(rawCfg *RawConfig) *NTP {
	cfg := rawCfg.NTP
	ntpCfg := &NTP{
		Enable:        cfg.Enable,
		Server:        cfg.Server,
		Port:          cfg.ServerPort,
		Interval:      cfg.Interval,
		DialerProxy:   cfg.DialerProxy,
		WriteToSystem: cfg.WriteToSystem,
	}
	return ntpCfg
}

func parseDNS(rawCfg *RawConfig, hosts *trie.DomainTrie[resolver.HostValue], rules []C.Rule, ruleProviders map[string]providerTypes.RuleProvider) (*DNS, error) {
	cfg := rawCfg.DNS
	if cfg.Enable && len(cfg.NameServer) == 0 {
		return nil, fmt.Errorf("if DNS configuration is turned on, NameServer cannot be empty")
	}

	dnsCfg := &DNS{
		Enable:       cfg.Enable,
		Listen:       cfg.Listen,
		PreferH3:     cfg.PreferH3,
		IPv6Timeout:  cfg.IPv6Timeout,
		IPv6:         cfg.IPv6,
		EnhancedMode: cfg.EnhancedMode,
		FallbackFilter: FallbackFilter{
			IPCIDR:  []netip.Prefix{},
			GeoSite: []router.DomainMatcher{},
		},
	}
	var err error
	if dnsCfg.NameServer, err = parseNameServer(cfg.NameServer, cfg.PreferH3); err != nil {
		return nil, err
	}

	if dnsCfg.Fallback, err = parseNameServer(cfg.Fallback, cfg.PreferH3); err != nil {
		return nil, err
	}

	if dnsCfg.NameServerPolicy, err = parseNameServerPolicy(cfg.NameServerPolicy, ruleProviders, cfg.PreferH3); err != nil {
		return nil, err
	}

	if dnsCfg.ProxyServerNameserver, err = parseNameServer(cfg.ProxyServerNameserver, cfg.PreferH3); err != nil {
		return nil, err
	}

	if len(cfg.DefaultNameserver) == 0 {
		return nil, errors.New("default nameserver should have at least one nameserver")
	}
	if dnsCfg.DefaultNameserver, err = parseNameServer(cfg.DefaultNameserver, cfg.PreferH3); err != nil {
		return nil, err
	}
	// check default nameserver is pure ip addr
	for _, ns := range dnsCfg.DefaultNameserver {
		if ns.Net == "system" {
			continue
		}
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

	fakeIPRange, err := netip.ParsePrefix(cfg.FakeIPRange)
	T.SetFakeIPRange(fakeIPRange)
	if cfg.EnhancedMode == C.DNSFakeIP {
		if err != nil {
			return nil, err
		}

		var host *trie.DomainTrie[struct{}]
		// fake ip skip host filter
		if len(cfg.FakeIPFilter) != 0 {
			host = trie.New[struct{}]()
			for _, domain := range cfg.FakeIPFilter {
				_ = host.Insert(domain, struct{}{})
			}
			host.Optimize()
		}

		if len(dnsCfg.Fallback) != 0 {
			if host == nil {
				host = trie.New[struct{}]()
			}
			for _, fb := range dnsCfg.Fallback {
				if net.ParseIP(fb.Addr) != nil {
					continue
				}
				_ = host.Insert(fb.Addr, struct{}{})
			}
			host.Optimize()
		}

		pool, err := fakeip.New(fakeip.Options{
			IPNet:       fakeIPRange,
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

	if cfg.CacheAlgorithm == "" || cfg.CacheAlgorithm == "lru" {
		dnsCfg.CacheAlgorithm = "lru"
	} else {
		dnsCfg.CacheAlgorithm = "arc"
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

func parseTun(rawTun RawTun, general *General) error {
	tunAddressPrefix := T.FakeIPRange()
	if !tunAddressPrefix.IsValid() {
		tunAddressPrefix = netip.MustParsePrefix("198.18.0.1/16")
	}
	tunAddressPrefix = netip.PrefixFrom(tunAddressPrefix.Addr(), 30)

	if !general.IPv6 || !verifyIP6() {
		rawTun.Inet6Address = nil
	}

	general.Tun = LC.Tun{
		Enable:              rawTun.Enable,
		Device:              rawTun.Device,
		Stack:               rawTun.Stack,
		DNSHijack:           rawTun.DNSHijack,
		AutoRoute:           rawTun.AutoRoute,
		AutoDetectInterface: rawTun.AutoDetectInterface,
		RedirectToTun:       rawTun.RedirectToTun,

		MTU:                      rawTun.MTU,
		GSO:                      rawTun.GSO,
		GSOMaxSize:               rawTun.GSOMaxSize,
		Inet4Address:             []netip.Prefix{tunAddressPrefix},
		Inet6Address:             rawTun.Inet6Address,
		StrictRoute:              rawTun.StrictRoute,
		Inet4RouteAddress:        rawTun.Inet4RouteAddress,
		Inet6RouteAddress:        rawTun.Inet6RouteAddress,
		Inet4RouteExcludeAddress: rawTun.Inet4RouteExcludeAddress,
		Inet6RouteExcludeAddress: rawTun.Inet6RouteExcludeAddress,
		IncludeInterface:         rawTun.IncludeInterface,
		ExcludeInterface:         rawTun.ExcludeInterface,
		IncludeUID:               rawTun.IncludeUID,
		IncludeUIDRange:          rawTun.IncludeUIDRange,
		ExcludeUID:               rawTun.ExcludeUID,
		ExcludeUIDRange:          rawTun.ExcludeUIDRange,
		IncludeAndroidUser:       rawTun.IncludeAndroidUser,
		IncludePackage:           rawTun.IncludePackage,
		ExcludePackage:           rawTun.ExcludePackage,
		EndpointIndependentNat:   rawTun.EndpointIndependentNat,
		UDPTimeout:               rawTun.UDPTimeout,
		FileDescriptor:           rawTun.FileDescriptor,
		TableIndex:               rawTun.TableIndex,
	}

	return nil
}

func parseTuicServer(rawTuic RawTuicServer, general *General) error {
	general.TuicServer = LC.TuicServer{
		Enable:                rawTuic.Enable,
		Listen:                rawTuic.Listen,
		Token:                 rawTuic.Token,
		Users:                 rawTuic.Users,
		Certificate:           rawTuic.Certificate,
		PrivateKey:            rawTuic.PrivateKey,
		CongestionController:  rawTuic.CongestionController,
		MaxIdleTime:           rawTuic.MaxIdleTime,
		AuthenticationTimeout: rawTuic.AuthenticationTimeout,
		ALPN:                  rawTuic.ALPN,
		MaxUdpRelayPacketSize: rawTuic.MaxUdpRelayPacketSize,
		CWND:                  rawTuic.CWND,
	}
	return nil
}

func parseSniffer(snifferRaw RawSniffer) (*Sniffer, error) {
	sniffer := &Sniffer{
		Enable:          snifferRaw.Enable,
		ForceDnsMapping: snifferRaw.ForceDnsMapping,
		ParsePureIp:     snifferRaw.ParsePureIp,
	}
	loadSniffer := make(map[snifferTypes.Type]SNIFF.SnifferConfig)

	if len(snifferRaw.Sniff) != 0 {
		for sniffType, sniffConfig := range snifferRaw.Sniff {
			find := false
			ports, err := utils.NewUnsignedRangesFromList[uint16](sniffConfig.Ports)
			if err != nil {
				return nil, err
			}
			overrideDest := snifferRaw.OverrideDest
			if sniffConfig.OverrideDest != nil {
				overrideDest = *sniffConfig.OverrideDest
			}
			for _, snifferType := range snifferTypes.List {
				if snifferType.String() == strings.ToUpper(sniffType) {
					find = true
					loadSniffer[snifferType] = SNIFF.SnifferConfig{
						Ports:        ports,
						OverrideDest: overrideDest,
					}
				}
			}

			if !find {
				return nil, fmt.Errorf("not find the sniffer[%s]", sniffType)
			}
		}
	} else {
		if sniffer.Enable {
			// Deprecated: Use Sniff instead
			log.Warnln("Deprecated: Use Sniff instead")
		}
		globalPorts, err := utils.NewUnsignedRangesFromList[uint16](snifferRaw.Ports)
		if err != nil {
			return nil, err
		}

		for _, snifferName := range snifferRaw.Sniffing {
			find := false
			for _, snifferType := range snifferTypes.List {
				if snifferType.String() == strings.ToUpper(snifferName) {
					find = true
					loadSniffer[snifferType] = SNIFF.SnifferConfig{
						Ports:        globalPorts,
						OverrideDest: snifferRaw.OverrideDest,
					}
				}
			}

			if !find {
				return nil, fmt.Errorf("not find the sniffer[%s]", snifferName)
			}
		}
	}

	sniffer.Sniffers = loadSniffer

	forceDomainTrie := trie.New[struct{}]()
	for _, domain := range snifferRaw.ForceDomain {
		err := forceDomainTrie.Insert(domain, struct{}{})
		if err != nil {
			return nil, fmt.Errorf("error domian[%s] in force-domain, error:%v", domain, err)
		}
	}
	sniffer.ForceDomain = forceDomainTrie.NewDomainSet()

	skipDomainTrie := trie.New[struct{}]()
	for _, domain := range snifferRaw.SkipDomain {
		err := skipDomainTrie.Insert(domain, struct{}{})
		if err != nil {
			return nil, fmt.Errorf("error domian[%s] in force-domain, error:%v", domain, err)
		}
	}
	sniffer.SkipDomain = skipDomainTrie.NewDomainSet()

	return sniffer, nil
}
