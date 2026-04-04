package provider

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	regexp2 "github.com/dlclark/regexp2"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/common/yaml"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
)

var (
	errVehicleType = errors.New("unsupport vehicle type")
)

type healthCheckSchema struct {
	Enable         bool   `provider:"enable"`
	URL            string `provider:"url,omitempty"`
	Interval       int    `provider:"interval,omitempty"`
	TestTimeout    int    `provider:"timeout,omitempty"`
	Lazy           bool   `provider:"lazy,omitempty"`
	ExpectedStatus string `provider:"expected-status,omitempty"`
}

type proxyProviderSchema struct {
	Type                   string           `provider:"type"`
	Path                   string           `provider:"path,omitempty"`
	URL                    string           `provider:"url,omitempty"`
	Proxy                  string           `provider:"proxy,omitempty"`
	Interval               int              `provider:"interval,omitempty"`
	Filter                 string           `provider:"filter,omitempty"`
	ExcludeFilter          string           `provider:"exclude-filter,omitempty"`
	ExcludeType            string           `provider:"exclude-type,omitempty"`
	DialerProxy            string           `provider:"dialer-proxy,omitempty"`
	SizeLimit              int64            `provider:"size-limit,omitempty"`
	Payload                []map[string]any `provider:"payload,omitempty"`
	AutoCreateGroup        bool             `provider:"auto-create-group,omitempty"`
	AutoGroupFilter        string           `provider:"auto-group-filter,omitempty"`
	AutoGroupExcludeFilter string           `provider:"auto-group-exclude-filter,omitempty"`
	AutoGroupExcludeType   string           `provider:"auto-group-exclude-type,omitempty"`
	AutoImportRules        bool             `provider:"auto-import-rules,omitempty"`
	AutoRuleFilter         string           `provider:"auto-rule-filter,omitempty"`
	AutoRuleExcludeFilter  string           `provider:"auto-rule-exclude-filter,omitempty"`
	AutoGroupSync          bool             `provider:"auto-group-sync,omitempty"`

	HealthCheck healthCheckSchema   `provider:"health-check,omitempty"`
	Override    overrideSchema      `provider:"override,omitempty"`
	Header      map[string][]string `provider:"header,omitempty"`
}

func ParseProxyProvider(name string, mapping map[string]any) (P.ProxyProvider, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})

	schema := &proxyProviderSchema{
		HealthCheck: healthCheckSchema{
			Lazy: true,
		},
	}
	if err := decoder.Decode(mapping, schema); err != nil {
		return nil, err
	}

	expectedStatus, err := utils.NewUnsignedRanges[uint16](schema.HealthCheck.ExpectedStatus)
	if err != nil {
		return nil, err
	}

	var hcInterval uint
	if schema.HealthCheck.Enable {
		if schema.HealthCheck.Interval == 0 {
			schema.HealthCheck.Interval = 300
		}
		hcInterval = uint(schema.HealthCheck.Interval)
	}
	hc := NewHealthCheck([]C.Proxy{}, schema.HealthCheck.URL, uint(schema.HealthCheck.TestTimeout), hcInterval, schema.HealthCheck.Lazy, expectedStatus)

	parser, err := NewProxiesParser(name, schema.Filter, schema.ExcludeFilter, schema.ExcludeType, schema.DialerProxy, schema.Override)
	if err != nil {
		return nil, err
	}

	var vehicle P.Vehicle
	switch schema.Type {
	case "file":
		path := C.Path.Resolve(schema.Path)
		if !C.Path.IsSafePath(path) {
			return nil, C.Path.ErrNotSafePath(path)
		}
		vehicle = resource.NewFileVehicle(path)
	case "http":
		path := C.Path.GetPathByHash("proxies", schema.URL)
		if schema.Path != "" {
			path = C.Path.Resolve(schema.Path)
			if !C.Path.IsSafePath(path) {
				return nil, C.Path.ErrNotSafePath(path)
			}
		}
		vehicle = resource.NewHTTPVehicle(schema.URL, path, schema.Proxy, schema.Header, resource.DefaultHttpTimeout, schema.SizeLimit)
	case "inline":
		return NewInlineProvider(name, schema.Payload, parser, hc)
	default:
		return nil, fmt.Errorf("%w: %s", errVehicleType, schema.Type)
	}

	interval := time.Duration(uint(schema.Interval)) * time.Second

	return NewProxySetProvider(name, interval, schema.Payload, parser, vehicle, hc)
}

func ParseProxyProviderForAutoGroupWithFilter(providersConfig map[string]map[string]any, autoGroups *[]map[string]any, ipv6 bool) error {
	decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})

	for name, mapping := range providersConfig {
		schema := &proxyProviderSchema{}
		if err := decoder.Decode(mapping, schema); err != nil {
			return fmt.Errorf("parse proxy provider %s for auto-group error: %w", name, err)
		}

		if !schema.AutoCreateGroup {
			log.Debugln("[AutoCreateGroup] provider [%s] auto-create-group is disabled, skipping", name)
			continue
		}

		vehicleType := schema.Type
		if vehicleType != "file" && vehicleType != "http" {
			log.Debugln("[AutoCreateGroup] provider [%s] vehicle type %s does not support auto-create-group, skipping", name, vehicleType)
			continue
		}

		var providerPath string
		switch vehicleType {
		case "file":
			providerPath = C.Path.Resolve(schema.Path)
			if !C.Path.IsSafePath(providerPath) {
				log.Warnln("[AutoCreateGroup] provider [%s] path [%s] is not safe, skipping", name, providerPath)
				continue
			}
		case "http":
			providerPath = C.Path.GetPathByHash("proxies", schema.URL)
			if schema.Path != "" {
				providerPath = C.Path.Resolve(schema.Path)
				if !C.Path.IsSafePath(providerPath) {
					log.Warnln("[AutoCreateGroup] provider [%s] path [%s] is not safe, skipping", name, providerPath)
					continue
				}
			}
		}

		log.Debugln("[AutoCreateGroup] provider [%s] reading file: %s", name, providerPath)

		buf, err := os.ReadFile(providerPath)
		if err != nil {
			return fmt.Errorf("read provider [%s] file error: %w", name, err)
		}

		var rawCfg rawConfig
		if err := yaml.Unmarshal(buf, &rawCfg); err != nil {
			return fmt.Errorf("parse provider [%s] file error: %w", name, err)
		}

		for _, group := range rawCfg.ProxyGroups {
			groupName, hasName := group["name"].(string)
			if !hasName {
				log.Warnln("[AutoCreateGroup] skip group without name in provider [%s]", name)
				continue
			}

			autoGroupName := name + "-" + groupName
			autoGroupConfig := map[string]any{
				"name": autoGroupName,
			}

			log.Debugln("[AutoCreateGroup] provider [%s] group [%s] raw proxies type: %T", name, groupName, group["proxies"])
			if rawProxies := group["proxies"]; rawProxies != nil {
				log.Debugln("[AutoCreateGroup] provider [%s] group [%s] raw proxies value: %v", name, groupName, rawProxies)
			}

			if groupType, ok := group["type"].(string); ok {
				autoGroupConfig["type"] = groupType
			}

			autoGroupConfig["use"] = []string{name}

			if filter, ok := group["filter"].(string); ok {
				autoGroupConfig["filter"] = filter
				log.Debugln("[AutoCreateGroup] provider [%s] group [%s] has filter: %s", name, groupName, filter)
			} else if schema.AutoGroupFilter != "" {
				autoGroupConfig["filter"] = schema.AutoGroupFilter
				log.Debugln("[AutoCreateGroup] provider [%s] group [%s] using auto-group-filter: %s (original group has no filter)", name, groupName, schema.AutoGroupFilter)
			} else if schema.AutoGroupSync {
				log.Debugln("[AutoCreateGroup] provider [%s] group [%s] auto-group-sync is enabled, no filter will be set", name, groupName)
			} else if originalProxies, ok := group["proxies"].([]any); ok && len(originalProxies) > 0 {
				var proxyNames []string
				for _, p := range originalProxies {
					if s, ok := p.(string); ok {
						proxyNames = append(proxyNames, s)
					}
				}
				if len(proxyNames) > 0 {
					autoGroupConfig["filter"] = "auto:" + strings.Join(proxyNames, "|")
					log.Debugln("[AutoCreateGroup] provider [%s] group [%s] auto-generated filter: %s (from %d original proxies)", name, groupName, autoGroupConfig["filter"], len(proxyNames))
				}
			} else {
				log.Debugln("[AutoCreateGroup] provider [%s] group [%s] no filter set (no auto-group-filter, no original proxies)", name, groupName)
			}

			if excludeFilter, ok := group["exclude-filter"].(string); ok {
				autoGroupConfig["exclude-filter"] = excludeFilter
				log.Debugln("[AutoCreateGroup] provider [%s] group [%s] has exclude-filter: %s", name, groupName, excludeFilter)
			} else if schema.AutoGroupExcludeFilter != "" {
				autoGroupConfig["exclude-filter"] = schema.AutoGroupExcludeFilter
				log.Debugln("[AutoCreateGroup] provider [%s] group [%s] using auto-group-exclude-filter: %s", name, groupName, schema.AutoGroupExcludeFilter)
			}

			if excludeType, ok := group["exclude-type"].(string); ok {
				autoGroupConfig["exclude-type"] = excludeType
			} else if schema.AutoGroupExcludeType != "" {
				autoGroupConfig["exclude-type"] = schema.AutoGroupExcludeType
			} else if !ipv6 {
				autoGroupConfig["exclude-type"] = "IPv6"
				log.Debugln("[AutoCreateGroup] provider [%s] group [%s] auto-exclude IPv6 (ipv6 disabled)", name, groupName)
			}

			for key, value := range group {
				if key == "name" || key == "type" || key == "proxies" || key == "use" || key == "filter" || key == "exclude-filter" || key == "exclude-type" {
					continue
				}
				autoGroupConfig[key] = value
			}

			*autoGroups = append(*autoGroups, autoGroupConfig)
			log.Infoln("[AutoCreateGroup] provider [%s] auto-created proxy-group: %s (type: %s, use: %s)",
				name, groupName, autoGroupConfig["type"], autoGroupConfig["use"])
		}
	}

	return nil
}

type rawConfig struct {
	ProxyGroups []map[string]any `yaml:"proxy-groups"`
	Proxies     []map[string]any `yaml:"proxies"`
	Rules       []string         `yaml:"rules"`
}

func (r *rawConfig) getProxyNames() []string {
	names := make([]string, 0, len(r.Proxies))
	for _, proxy := range r.Proxies {
		if name, ok := proxy["name"].(string); ok {
			names = append(names, name)
		}
	}
	return names
}

func ParseProxyProviderForAutoImportRules(providersConfig map[string]map[string]any) (map[string][]string, error) {
	autoRulesMap := make(map[string][]string)
	decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})

	for name, mapping := range providersConfig {
		schema := &proxyProviderSchema{}
		if err := decoder.Decode(mapping, schema); err != nil {
			return nil, fmt.Errorf("parse proxy provider %s for auto-import-rules error: %w", name, err)
		}

		if !schema.AutoImportRules {
			log.Debugln("[AutoImportRules] provider [%s] auto-import-rules is disabled, skipping", name)
			continue
		}

		vehicleType := schema.Type
		if vehicleType != "file" && vehicleType != "http" {
			log.Debugln("[AutoImportRules] provider [%s] vehicle type %s does not support auto-import-rules, skipping", name, vehicleType)
			continue
		}

		var providerPath string
		switch vehicleType {
		case "file":
			providerPath = C.Path.Resolve(schema.Path)
			if !C.Path.IsSafePath(providerPath) {
				log.Warnln("[AutoImportRules] provider [%s] path [%s] is not safe, skipping", name, providerPath)
				continue
			}
		case "http":
			providerPath = C.Path.GetPathByHash("proxies", schema.URL)
			if schema.Path != "" {
				providerPath = C.Path.Resolve(schema.Path)
				if !C.Path.IsSafePath(providerPath) {
					log.Warnln("[AutoImportRules] provider [%s] path [%s] is not safe, skipping", name, providerPath)
					continue
				}
			}
		}

		log.Debugln("[AutoImportRules] provider [%s] reading file: %s", name, providerPath)

		buf, err := os.ReadFile(providerPath)
		if err != nil {
			return nil, fmt.Errorf("read provider [%s] file error: %w", name, err)
		}

		var rawCfg rawConfig
		if err := yaml.Unmarshal(buf, &rawCfg); err != nil {
			return nil, fmt.Errorf("parse provider [%s] file error: %w", name, err)
		}

		autoRulesMap[name] = []string{}
		for _, rule := range rawCfg.Rules {
			shouldAdd := true

			if schema.AutoRuleExcludeFilter != "" {
				excludeReg := regexp2.MustCompile(schema.AutoRuleExcludeFilter, regexp2.None)
				if mat, _ := excludeReg.MatchString(rule); mat {
					log.Debugln("[AutoImportRules] provider [%s] rule [%s] matched exclude-filter, skipping", name, rule)
					shouldAdd = false
				}
			}

			if shouldAdd && schema.AutoRuleFilter != "" {
				filterReg := regexp2.MustCompile(schema.AutoRuleFilter, regexp2.None)
				if mat, _ := filterReg.MatchString(rule); !mat {
					log.Debugln("[AutoImportRules] provider [%s] rule [%s] did not match filter, skipping", name, rule)
					shouldAdd = false
				}
			}

			if shouldAdd {
				autoRulesMap[name] = append(autoRulesMap[name], rule)
				log.Infoln("[AutoImportRules] provider [%s] imported rule: %s", name, rule)
			}
		}
	}

	return autoRulesMap, nil
}
