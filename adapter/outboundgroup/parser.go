package outboundgroup

import (
	"errors"
	"fmt"
	"strings"

	"github.com/dlclark/regexp2"

	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/networkpolicy"
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
}

func ParseProxyGroup(config map[string]any, proxyMap map[string]C.Proxy, providersMap map[string]P.ProxyProvider, AllProxies []string, AllProviders []string, AllNetworks []string, AllProxyNames []string) (C.ProxyAdapter, error) {
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

	// network-policy is a select-only subfield (architecture §5.8.1).
	// Presence on any other group type is a parse-time configuration error.
	// Presence detection is key-based, so `network-policy:` (null value) is
	// treated the same as a populated field — ParseGroupPolicy will reject
	// it with "expected map" and users who want "no policy" must omit the
	// field entirely.
	_, hasNetworkPolicy := config["network-policy"]
	if hasNetworkPolicy && groupOption.Type != "select" {
		return nil, fmt.Errorf("%s: network-policy is only supported on select groups (got %q)", groupOption.Name, groupOption.Type)
	}

	if _, ok := config["routing-mark"]; ok {
		log.Errorln("The group [%s] with routing-mark configuration was removed, please set it directly on the proxy instead", groupOption.Name)
	}
	if _, ok := config["interface-name"]; ok {
		log.Errorln("The group [%s] with interface-name configuration was removed, please set it directly on the proxy instead", groupOption.Name)
	}
	if _, ok := config["dialer-proxy"]; ok {
		log.Errorln("The group [%s] with dialer-proxy configuration is not allowed, please set it directly on the proxy instead", groupOption.Name)
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
		selector := NewSelector(groupOption, providers)
		// Build GroupSource from the post-expansion static proxy set and the
		// external-provider presence (architecture §5.8.1). StaticProxies
		// must reflect the runtime-visible candidate set after filtering —
		// GroupBase.GetProxies applies ExcludeFilter / ExcludeType on top of
		// the compatible-provider output at runtime, so the parse-time check
		// must apply the same filters to preserve the "parse-time visible ⇒
		// runtime reachable" invariant promised by GroupSource's docs.
		// (Filter itself is already applied in the include-all-proxies
		// expansion path above, so only the Exclude* side is handled here.)
		//
		// The inner CompatibleProvider wrapping Proxies: is not an "external"
		// provider for validation purposes — tolerant-branch validation
		// applies only to real providers referenced via `use:` /
		// include-all-providers.
		gs := networkpolicy.GroupSource{
			StaticProxies: filterStaticProxies(groupOption.Proxies, groupOption.ExcludeFilter, groupOption.ExcludeType, proxyMap),
			HasProvider:   len(groupOption.Use) > 0,
			Filter:        groupOption.Filter,
			ExcludeFilter: groupOption.ExcludeFilter,
			ExcludeType:   groupOption.ExcludeType,
		}
		if hasNetworkPolicy {
			// AllProxyNames is the stable pre-computed global proxy-name set
			// (all built-ins, top-level `proxies:`, and every declared proxy
			// group name). It is NOT derived from proxyMap at this moment,
			// because proxyMap only contains groups parsed so far — using it
			// would make the §5.8.1 "globally known vs. truly absent"
			// distinction order-dependent (proxyGroupsDagSort topologically
			// sorts groups but groups without mutual dependencies can appear
			// in any order, destabilizing validation across runs).
			policy, err := networkpolicy.ParseGroupPolicy(config["network-policy"], AllNetworks, AllProxyNames, gs)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", groupName, err)
			}
			selector.SetNetworkPolicy(policy, gs)
		} else {
			selector.SetNetworkPolicy(networkpolicy.GroupPolicy{}, gs)
		}
		group = selector
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

// filterStaticProxies applies a group's ExcludeFilter / ExcludeType rules to
// the (already Filter-applied) static proxy name list, producing the
// parse-time candidate set that the network-policy validator can trust.
//
// GroupBase.GetProxies applies ExcludeFilter / ExcludeType unconditionally to
// both the compatible-provider-wrapped static proxies and external provider
// output (adapter/outboundgroup/groupbase.go). For the network-policy
// parse-time check to correctly preserve the "visible at parse time ⇒
// reachable at runtime" invariant (architecture §5.8.1), the static list
// must go through the same Exclude* filtering before being recorded as
// GroupSource.StaticProxies.
//
// Note: the regex split + compile logic here intentionally duplicates
// NewGroupBase in groupbase.go. The two are called independently (NewGroupBase
// for runtime, this for parse-time validation); keep them aligned by hand
// when editing either side.
//
// ExcludeType matching needs proxy type strings, which are only available
// via proxyMap. A name missing from proxyMap is kept in the result because
// a separately-failing lookup downstream (getProxies) will surface the bug
// on its own channel — the network-policy validator's job is narrow.
func filterStaticProxies(names []string, excludeFilter, excludeType string, proxyMap map[string]C.Proxy) []string {
	if len(names) == 0 {
		return nil
	}

	var excludeFilterRegs []*regexp2.Regexp
	if excludeFilter != "" {
		for _, f := range strings.Split(excludeFilter, "`") {
			excludeFilterRegs = append(excludeFilterRegs, regexp2.MustCompile(f, regexp2.None))
		}
	}
	var excludeTypeArr []string
	if excludeType != "" {
		excludeTypeArr = strings.Split(excludeType, "|")
	}

	if len(excludeFilterRegs) == 0 && len(excludeTypeArr) == 0 {
		// Common case: no exclude filters at all. Return a defensive copy so
		// downstream callers can't mutate the caller's slice.
		return append([]string(nil), names...)
	}

	out := make([]string, 0, len(names))
outer:
	for _, name := range names {
		for _, reg := range excludeFilterRegs {
			if mat, _ := reg.MatchString(name); mat {
				continue outer
			}
		}
		if len(excludeTypeArr) > 0 {
			if p, ok := proxyMap[name]; ok {
				t := p.Type().String()
				for _, et := range excludeTypeArr {
					if strings.EqualFold(t, et) {
						continue outer
					}
				}
			}
		}
		out = append(out, name)
	}
	return out
}

func addTestUrlToProviders(providers []P.ProxyProvider, url string, expectedStatus utils.IntRanges[uint16], filter string, interval uint) {
	if len(providers) == 0 || len(url) == 0 {
		return
	}

	for _, pd := range providers {
		pd.RegisterHealthCheckTask(url, expectedStatus, filter, interval)
	}
}
