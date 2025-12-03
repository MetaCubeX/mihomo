package outboundgroup

import (
	"errors"
	"fmt"
	"strings"

	"github.com/dlclark/regexp2"

	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
)

var (
	errFormat            = errors.New("format error")
	errType              = errors.New("unsupported type")
	errMissProxy         = errors.New("`use` or `proxies` missing")
	errDuplicateProvider = errors.New("duplicate provider name")
)

type GroupCommonOption struct {
	Name                string   `group:"name"`
	Type                string   `group:"type"`
	Proxies             []string `group:"proxies,omitempty"`
	Use                 []string `group:"use,omitempty"`
	URL                 string   `group:"url,omitempty"`
	Interval            int      `group:"interval,omitempty"`
	TestTimeout         int      `group:"timeout,omitempty"`
	MaxFailedTimes      int      `group:"max-failed-times,omitempty"`
	Lazy                bool     `group:"lazy,omitempty"`
	DisableUDP          bool     `group:"disable-udp,omitempty"`
	Filter              string   `group:"filter,omitempty"`
	ExcludeFilter       string   `group:"exclude-filter,omitempty"`
	ExcludeType         string   `group:"exclude-type,omitempty"`
	ExpectedStatus      string   `group:"expected-status,omitempty"`
	IncludeAll          bool     `group:"include-all,omitempty"`
	IncludeAllProxies   bool     `group:"include-all-proxies,omitempty"`
	IncludeAllProviders bool     `group:"include-all-providers,omitempty"`
	Hidden              bool     `group:"hidden,omitempty"`
	Icon                string   `group:"icon,omitempty"`

	// removed configs, only for error logging
	Interface   string `group:"interface-name,omitempty"`
	RoutingMark int    `group:"routing-mark,omitempty"`
}

func ParseProxyGroup(config map[string]any, proxyMap map[string]C.Proxy, providersMap map[string]P.ProxyProvider, AllProxies []string, AllProviders []string) (C.ProxyAdapter, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "group", WeaklyTypedInput: true})

	groupOption := &GroupCommonOption{
		Lazy: true,
	}
	if err := decoder.Decode(config, groupOption); err != nil {
		return nil, errFormat
	}

	if groupOption.Type == "" || groupOption.Name == "" {
		return nil, errFormat
	}

	if groupOption.RoutingMark != 0 {
		log.Errorln("The group [%s] with routing-mark configuration was removed, please set it directly on the proxy instead", groupOption.Name)
	}
	if groupOption.Interface != "" {
		log.Errorln("The group [%s] with interface-name configuration was removed, please set it directly on the proxy instead", groupOption.Name)
	}

	groupName := groupOption.Name

	providers := []P.ProxyProvider{}

	if groupOption.IncludeAll {
		groupOption.IncludeAllProviders = true
		groupOption.IncludeAllProxies = true
	}

	if groupOption.IncludeAllProviders {
		groupOption.Use = AllProviders
	}
	if groupOption.IncludeAllProxies {
		if groupOption.Filter != "" {
			var filterRegs []*regexp2.Regexp
			for _, filter := range strings.Split(groupOption.Filter, "`") {
				filterReg := regexp2.MustCompile(filter, regexp2.None)
				filterRegs = append(filterRegs, filterReg)
			}
			for _, p := range AllProxies {
				for _, filterReg := range filterRegs {
					if mat, _ := filterReg.MatchString(p); mat {
						groupOption.Proxies = append(groupOption.Proxies, p)
					}
				}
			}
		} else {
			groupOption.Proxies = append(groupOption.Proxies, AllProxies...)
		}
		if len(groupOption.Proxies) == 0 && len(groupOption.Use) == 0 {
			groupOption.Proxies = []string{"COMPATIBLE"}
		}
	}

	if len(groupOption.Proxies) == 0 && len(groupOption.Use) == 0 {
		return nil, fmt.Errorf("%s: %w", groupName, errMissProxy)
	}

	expectedStatus, err := utils.NewUnsignedRanges[uint16](groupOption.ExpectedStatus)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", groupName, err)
	}

	status := strings.TrimSpace(groupOption.ExpectedStatus)
	if status == "" {
		status = "*"
	}
	groupOption.ExpectedStatus = status

	if len(groupOption.Use) != 0 {
		PDs, err := getProviders(providersMap, groupOption.Use)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", groupName, err)
		}

		// if test URL is empty, use the first health check URL of providers
		if groupOption.URL == "" {
			for _, pd := range PDs {
				if pd.HealthCheckURL() != "" {
					groupOption.URL = pd.HealthCheckURL()
					break
				}
			}
			if groupOption.URL == "" {
				groupOption.URL = C.DefaultTestURL
			}
		} else {
			addTestUrlToProviders(PDs, groupOption.URL, expectedStatus, groupOption.Filter, uint(groupOption.Interval))
		}
		providers = append(providers, PDs...)
	}

	if len(groupOption.Proxies) != 0 {
		ps, err := getProxies(proxyMap, groupOption.Proxies)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", groupName, err)
		}

		if _, ok := providersMap[groupName]; ok {
			return nil, fmt.Errorf("%s: %w", groupName, errDuplicateProvider)
		}

		if groupOption.URL == "" {
			groupOption.URL = C.DefaultTestURL
		}

		// select don't need auto health check
		if groupOption.Type != "select" && groupOption.Type != "relay" {
			if groupOption.Interval == 0 {
				groupOption.Interval = 300
			}
		}

		hc := provider.NewHealthCheck(ps, groupOption.URL, uint(groupOption.TestTimeout), uint(groupOption.Interval), groupOption.Lazy, expectedStatus)

		pd, err := provider.NewCompatibleProvider(groupName, ps, hc)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", groupName, err)
		}

		providers = append([]P.ProxyProvider{pd}, providers...)
		providersMap[groupName] = pd
	}

	var group C.ProxyAdapter
	switch groupOption.Type {
	case "url-test":
		opts := parseURLTestOption(config)
		group = NewURLTest(groupOption, providers, opts...)
	case "select":
		group = NewSelector(groupOption, providers)
	case "fallback":
		group = NewFallback(groupOption, providers)
	case "load-balance":
		strategy := parseStrategy(config)
		return NewLoadBalance(groupOption, providers, strategy)
	case "relay":
		return nil, fmt.Errorf("%w: The group [%s] with relay type was removed, please using dialer-proxy instead", errType, groupName)
	default:
		return nil, fmt.Errorf("%w: %s", errType, groupOption.Type)
	}

	return group, nil
}

func getProxies(mapping map[string]C.Proxy, list []string) ([]C.Proxy, error) {
	var ps []C.Proxy
	for _, name := range list {
		p, ok := mapping[name]
		if !ok {
			return nil, fmt.Errorf("'%s' not found", name)
		}
		ps = append(ps, p)
	}
	return ps, nil
}

func getProviders(mapping map[string]P.ProxyProvider, list []string) ([]P.ProxyProvider, error) {
	var ps []P.ProxyProvider
	for _, name := range list {
		p, ok := mapping[name]
		if !ok {
			return nil, fmt.Errorf("'%s' not found", name)
		}

		if p.VehicleType() == P.Compatible {
			return nil, fmt.Errorf("proxy group %s can't contains in `use`", name)
		}
		ps = append(ps, p)
	}
	return ps, nil
}

func addTestUrlToProviders(providers []P.ProxyProvider, url string, expectedStatus utils.IntRanges[uint16], filter string, interval uint) {
	if len(providers) == 0 || len(url) == 0 {
		return
	}

	for _, pd := range providers {
		pd.RegisterHealthCheckTask(url, expectedStatus, filter, interval)
	}
}
