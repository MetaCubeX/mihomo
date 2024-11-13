package route

import (
	"net/http"
	"net/netip"
	"path/filepath"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/updater"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	P "github.com/metacubex/mihomo/listener"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func configRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getConfigs)
	if !embedMode { // disallow update/patch configs in embed mode
		r.Put("/", updateConfigs)
		r.Post("/geo", updateGeoDatabases)
		r.Patch("/", patchConfigs)
	}
	return r
}

type configSchema struct {
	Port              *int               `json:"port"`
	SocksPort         *int               `json:"socks-port"`
	RedirPort         *int               `json:"redir-port"`
	TProxyPort        *int               `json:"tproxy-port"`
	MixedPort         *int               `json:"mixed-port"`
	Tun               *tunSchema         `json:"tun"`
	TuicServer        *tuicServerSchema  `json:"tuic-server"`
	ShadowSocksConfig *string            `json:"ss-config"`
	VmessConfig       *string            `json:"vmess-config"`
	TcptunConfig      *string            `json:"tcptun-config"`
	UdptunConfig      *string            `json:"udptun-config"`
	AllowLan          *bool              `json:"allow-lan"`
	SkipAuthPrefixes  *[]netip.Prefix    `json:"skip-auth-prefixes"`
	LanAllowedIPs     *[]netip.Prefix    `json:"lan-allowed-ips"`
	LanDisAllowedIPs  *[]netip.Prefix    `json:"lan-disallowed-ips"`
	BindAddress       *string            `json:"bind-address"`
	Mode              *tunnel.TunnelMode `json:"mode"`
	LogLevel          *log.LogLevel      `json:"log-level"`
	IPv6              *bool              `json:"ipv6"`
	Sniffing          *bool              `json:"sniffing"`
	TcpConcurrent     *bool              `json:"tcp-concurrent"`
	InterfaceName     *string            `json:"interface-name"`
}

type tunSchema struct {
	Enable              bool        `yaml:"enable" json:"enable"`
	Device              *string     `yaml:"device" json:"device"`
	Stack               *C.TUNStack `yaml:"stack" json:"stack"`
	DNSHijack           *[]string   `yaml:"dns-hijack" json:"dns-hijack"`
	AutoRoute           *bool       `yaml:"auto-route" json:"auto-route"`
	AutoDetectInterface *bool       `yaml:"auto-detect-interface" json:"auto-detect-interface"`

	MTU        *uint32 `yaml:"mtu" json:"mtu,omitempty"`
	GSO        *bool   `yaml:"gso" json:"gso,omitempty"`
	GSOMaxSize *uint32 `yaml:"gso-max-size" json:"gso-max-size,omitempty"`
	//Inet4Address           *[]netip.Prefix `yaml:"inet4-address" json:"inet4-address,omitempty"`
	Inet6Address           *[]netip.Prefix `yaml:"inet6-address" json:"inet6-address,omitempty"`
	IPRoute2TableIndex     *int            `yaml:"iproute2-table-index" json:"iproute2-table-index,omitempty"`
	IPRoute2RuleIndex      *int            `yaml:"iproute2-rule-index" json:"iproute2-rule-index,omitempty"`
	AutoRedirect           *bool           `yaml:"auto-redirect" json:"auto-redirect,omitempty"`
	AutoRedirectInputMark  *uint32         `yaml:"auto-redirect-input-mark" json:"auto-redirect-input-mark,omitempty"`
	AutoRedirectOutputMark *uint32         `yaml:"auto-redirect-output-mark" json:"auto-redirect-output-mark,omitempty"`
	StrictRoute            *bool           `yaml:"strict-route" json:"strict-route,omitempty"`
	RouteAddress           *[]netip.Prefix `yaml:"route-address" json:"route-address,omitempty"`
	RouteAddressSet        *[]string       `yaml:"route-address-set" json:"route-address-set,omitempty"`
	RouteExcludeAddress    *[]netip.Prefix `yaml:"route-exclude-address" json:"route-exclude-address,omitempty"`
	RouteExcludeAddressSet *[]string       `yaml:"route-exclude-address-set" json:"route-exclude-address-set,omitempty"`
	IncludeInterface       *[]string       `yaml:"include-interface" json:"include-interface,omitempty"`
	ExcludeInterface       *[]string       `yaml:"exclude-interface" json:"exclude-interface,omitempty"`
	IncludeUID             *[]uint32       `yaml:"include-uid" json:"include-uid,omitempty"`
	IncludeUIDRange        *[]string       `yaml:"include-uid-range" json:"include-uid-range,omitempty"`
	ExcludeUID             *[]uint32       `yaml:"exclude-uid" json:"exclude-uid,omitempty"`
	ExcludeUIDRange        *[]string       `yaml:"exclude-uid-range" json:"exclude-uid-range,omitempty"`
	IncludeAndroidUser     *[]int          `yaml:"include-android-user" json:"include-android-user,omitempty"`
	IncludePackage         *[]string       `yaml:"include-package" json:"include-package,omitempty"`
	ExcludePackage         *[]string       `yaml:"exclude-package" json:"exclude-package,omitempty"`
	EndpointIndependentNat *bool           `yaml:"endpoint-independent-nat" json:"endpoint-independent-nat,omitempty"`
	UDPTimeout             *int64          `yaml:"udp-timeout" json:"udp-timeout,omitempty"`
	FileDescriptor         *int            `yaml:"file-descriptor" json:"file-descriptor"`

	Inet4RouteAddress        *[]netip.Prefix `yaml:"inet4-route-address" json:"inet4-route-address,omitempty"`
	Inet6RouteAddress        *[]netip.Prefix `yaml:"inet6-route-address" json:"inet6-route-address,omitempty"`
	Inet4RouteExcludeAddress *[]netip.Prefix `yaml:"inet4-route-exclude-address" json:"inet4-route-exclude-address,omitempty"`
	Inet6RouteExcludeAddress *[]netip.Prefix `yaml:"inet6-route-exclude-address" json:"inet6-route-exclude-address,omitempty"`
}

type tuicServerSchema struct {
	Enable                bool               `yaml:"enable" json:"enable"`
	Listen                *string            `yaml:"listen" json:"listen"`
	Token                 *[]string          `yaml:"token" json:"token"`
	Users                 *map[string]string `yaml:"users" json:"users,omitempty"`
	Certificate           *string            `yaml:"certificate" json:"certificate"`
	PrivateKey            *string            `yaml:"private-key" json:"private-key"`
	CongestionController  *string            `yaml:"congestion-controller" json:"congestion-controller,omitempty"`
	MaxIdleTime           *int               `yaml:"max-idle-time" json:"max-idle-time,omitempty"`
	AuthenticationTimeout *int               `yaml:"authentication-timeout" json:"authentication-timeout,omitempty"`
	ALPN                  *[]string          `yaml:"alpn" json:"alpn,omitempty"`
	MaxUdpRelayPacketSize *int               `yaml:"max-udp-relay-packet-size" json:"max-udp-relay-packet-size,omitempty"`
	CWND                  *int               `yaml:"cwnd" json:"cwnd,omitempty"`
}

func getConfigs(w http.ResponseWriter, r *http.Request) {
	general := executor.GetGeneral()
	render.JSON(w, r, general)
}

func pointerOrDefault[T any](p *T, def T) T {
	if p != nil {
		return *p
	}
	return def
}

func pointerOrDefaultTun(p *tunSchema, def LC.Tun) LC.Tun {
	if p != nil {
		def.Enable = p.Enable
		if p.Device != nil {
			def.Device = *p.Device
		}
		if p.Stack != nil {
			def.Stack = *p.Stack
		}
		if p.DNSHijack != nil {
			def.DNSHijack = *p.DNSHijack
		}
		if p.AutoRoute != nil {
			def.AutoRoute = *p.AutoRoute
		}
		if p.AutoDetectInterface != nil {
			def.AutoDetectInterface = *p.AutoDetectInterface
		}
		if p.MTU != nil {
			def.MTU = *p.MTU
		}
		if p.GSO != nil {
			def.GSO = *p.GSO
		}
		if p.GSOMaxSize != nil {
			def.GSOMaxSize = *p.GSOMaxSize
		}
		//if p.Inet4Address != nil {
		//	def.Inet4Address = *p.Inet4Address
		//}
		if p.Inet6Address != nil {
			def.Inet6Address = *p.Inet6Address
		}
		if p.IPRoute2TableIndex != nil {
			def.IPRoute2TableIndex = *p.IPRoute2TableIndex
		}
		if p.IPRoute2RuleIndex != nil {
			def.IPRoute2RuleIndex = *p.IPRoute2RuleIndex
		}
		if p.AutoRedirect != nil {
			def.AutoRedirect = *p.AutoRedirect
		}
		if p.AutoRedirectInputMark != nil {
			def.AutoRedirectInputMark = *p.AutoRedirectInputMark
		}
		if p.AutoRedirectOutputMark != nil {
			def.AutoRedirectOutputMark = *p.AutoRedirectOutputMark
		}
		if p.StrictRoute != nil {
			def.StrictRoute = *p.StrictRoute
		}
		if p.RouteAddress != nil {
			def.RouteAddress = *p.RouteAddress
		}
		if p.RouteAddressSet != nil {
			def.RouteAddressSet = *p.RouteAddressSet
		}
		if p.RouteExcludeAddress != nil {
			def.RouteExcludeAddress = *p.RouteExcludeAddress
		}
		if p.RouteExcludeAddressSet != nil {
			def.RouteExcludeAddressSet = *p.RouteExcludeAddressSet
		}
		if p.Inet4RouteAddress != nil {
			def.Inet4RouteAddress = *p.Inet4RouteAddress
		}
		if p.Inet6RouteAddress != nil {
			def.Inet6RouteAddress = *p.Inet6RouteAddress
		}
		if p.Inet4RouteExcludeAddress != nil {
			def.Inet4RouteExcludeAddress = *p.Inet4RouteExcludeAddress
		}
		if p.Inet6RouteExcludeAddress != nil {
			def.Inet6RouteExcludeAddress = *p.Inet6RouteExcludeAddress
		}
		if p.IncludeInterface != nil {
			def.IncludeInterface = *p.IncludeInterface
		}
		if p.ExcludeInterface != nil {
			def.ExcludeInterface = *p.ExcludeInterface
		}
		if p.IncludeUID != nil {
			def.IncludeUID = *p.IncludeUID
		}
		if p.IncludeUIDRange != nil {
			def.IncludeUIDRange = *p.IncludeUIDRange
		}
		if p.ExcludeUID != nil {
			def.ExcludeUID = *p.ExcludeUID
		}
		if p.ExcludeUIDRange != nil {
			def.ExcludeUIDRange = *p.ExcludeUIDRange
		}
		if p.IncludeAndroidUser != nil {
			def.IncludeAndroidUser = *p.IncludeAndroidUser
		}
		if p.IncludePackage != nil {
			def.IncludePackage = *p.IncludePackage
		}
		if p.ExcludePackage != nil {
			def.ExcludePackage = *p.ExcludePackage
		}
		if p.EndpointIndependentNat != nil {
			def.EndpointIndependentNat = *p.EndpointIndependentNat
		}
		if p.UDPTimeout != nil {
			def.UDPTimeout = *p.UDPTimeout
		}
		if p.FileDescriptor != nil {
			def.FileDescriptor = *p.FileDescriptor
		}
	}
	return def
}

func pointerOrDefaultTuicServer(p *tuicServerSchema, def LC.TuicServer) LC.TuicServer {
	if p != nil {
		def.Enable = p.Enable
		if p.Listen != nil {
			def.Listen = *p.Listen
		}
		if p.Token != nil {
			def.Token = *p.Token
		}
		if p.Users != nil {
			def.Users = *p.Users
		}
		if p.Certificate != nil {
			def.Certificate = *p.Certificate
		}
		if p.PrivateKey != nil {
			def.PrivateKey = *p.PrivateKey
		}
		if p.CongestionController != nil {
			def.CongestionController = *p.CongestionController
		}
		if p.MaxIdleTime != nil {
			def.MaxIdleTime = *p.MaxIdleTime
		}
		if p.AuthenticationTimeout != nil {
			def.AuthenticationTimeout = *p.AuthenticationTimeout
		}
		if p.ALPN != nil {
			def.ALPN = *p.ALPN
		}
		if p.MaxUdpRelayPacketSize != nil {
			def.MaxUdpRelayPacketSize = *p.MaxUdpRelayPacketSize
		}
		if p.CWND != nil {
			def.CWND = *p.CWND
		}
	}
	return def
}

func patchConfigs(w http.ResponseWriter, r *http.Request) {
	general := &configSchema{}
	if err := render.DecodeJSON(r.Body, &general); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	if general.AllowLan != nil {
		P.SetAllowLan(*general.AllowLan)
	}

	if general.SkipAuthPrefixes != nil {
		inbound.SetSkipAuthPrefixes(*general.SkipAuthPrefixes)
	}

	if general.LanAllowedIPs != nil {
		inbound.SetAllowedIPs(*general.LanAllowedIPs)
	}

	if general.LanDisAllowedIPs != nil {
		inbound.SetDisAllowedIPs(*general.LanDisAllowedIPs)
	}

	if general.BindAddress != nil {
		P.SetBindAddress(*general.BindAddress)
	}

	if general.Sniffing != nil {
		tunnel.SetSniffing(*general.Sniffing)
	}

	if general.TcpConcurrent != nil {
		dialer.SetTcpConcurrent(*general.TcpConcurrent)
	}

	if general.InterfaceName != nil {
		dialer.DefaultInterface.Store(*general.InterfaceName)
	}

	ports := P.GetPorts()

	P.ReCreateHTTP(pointerOrDefault(general.Port, ports.Port), tunnel.Tunnel)
	P.ReCreateSocks(pointerOrDefault(general.SocksPort, ports.SocksPort), tunnel.Tunnel)
	P.ReCreateRedir(pointerOrDefault(general.RedirPort, ports.RedirPort), tunnel.Tunnel)
	P.ReCreateTProxy(pointerOrDefault(general.TProxyPort, ports.TProxyPort), tunnel.Tunnel)
	P.ReCreateMixed(pointerOrDefault(general.MixedPort, ports.MixedPort), tunnel.Tunnel)
	P.ReCreateTun(pointerOrDefaultTun(general.Tun, P.LastTunConf), tunnel.Tunnel)
	P.ReCreateShadowSocks(pointerOrDefault(general.ShadowSocksConfig, ports.ShadowSocksConfig), tunnel.Tunnel)
	P.ReCreateVmess(pointerOrDefault(general.VmessConfig, ports.VmessConfig), tunnel.Tunnel)
	P.ReCreateTuic(pointerOrDefaultTuicServer(general.TuicServer, P.LastTuicConf), tunnel.Tunnel)

	if general.Mode != nil {
		tunnel.SetMode(*general.Mode)
	}

	if general.LogLevel != nil {
		log.SetLevel(*general.LogLevel)
	}

	if general.IPv6 != nil {
		resolver.DisableIPv6 = !*general.IPv6
	}

	render.NoContent(w, r)
}

func updateConfigs(w http.ResponseWriter, r *http.Request) {
	req := struct {
		Path    string `json:"path"`
		Payload string `json:"payload"`
	}{}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	force := r.URL.Query().Get("force") == "true"
	var cfg *config.Config
	var err error

	if req.Payload != "" {
		cfg, err = executor.ParseWithBytes([]byte(req.Payload))
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
	} else {
		if req.Path == "" {
			req.Path = C.Path.Config()
		}
		if !filepath.IsAbs(req.Path) {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("path is not a absolute path"))
			return
		}

		cfg, err = executor.ParseWithPath(req.Path)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
	}

	executor.ApplyConfig(cfg, force)
	render.NoContent(w, r)
}

func updateGeoDatabases(w http.ResponseWriter, r *http.Request) {
	err := updater.UpdateGeoDatabases()
	if err != nil {
		log.Errorln("[GEO] update GEO databases failed: %v", err)
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError(err.Error()))
		return
	}

	render.NoContent(w, r)
}
