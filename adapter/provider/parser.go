package provider

import (
	"errors"
	"fmt"
	"time"

	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	types "github.com/metacubex/mihomo/constant/provider"
)

var (
	errVehicleType = errors.New("unsupport vehicle type")
	errSubPath     = errors.New("path is not subpath of home directory")
)

type healthCheckSchema struct {
	Enable         bool   `provider:"enable"`
	URL            string `provider:"url"`
	Interval       int    `provider:"interval"`
	TestTimeout    int    `provider:"timeout,omitempty"`
	Lazy           bool   `provider:"lazy,omitempty"`
	ExpectedStatus string `provider:"expected-status,omitempty"`
}

type OverrideSchema struct {
	UDP              *bool   `provider:"udp,omitempty"`
	Up               *string `provider:"up,omitempty"`
	Down             *string `provider:"down,omitempty"`
	DialerProxy      *string `provider:"dialer-proxy,omitempty"`
	SkipCertVerify   *bool   `provider:"skip-cert-verify,omitempty"`
	Interface        *string `provider:"interface-name,omitempty"`
	RoutingMark      *int    `provider:"routing-mark,omitempty"`
	IPVersion        *string `provider:"ip-version,omitempty"`
	AdditionalPrefix *string `provider:"additional-prefix,omitempty"`
	AdditionalSuffix *string `provider:"additional-suffix,omitempty"`
}

type proxyProviderSchema struct {
	Type          string `provider:"type"`
	Path          string `provider:"path,omitempty"`
	URL           string `provider:"url,omitempty"`
	Proxy         string `provider:"proxy,omitempty"`
	Interval      int    `provider:"interval,omitempty"`
	Filter        string `provider:"filter,omitempty"`
	ExcludeFilter string `provider:"exclude-filter,omitempty"`
	ExcludeType   string `provider:"exclude-type,omitempty"`
	DialerProxy   string `provider:"dialer-proxy,omitempty"`

	HealthCheck healthCheckSchema   `provider:"health-check,omitempty"`
	Override    OverrideSchema      `provider:"override,omitempty"`
	Header      map[string][]string `provider:"header,omitempty"`
}

func ParseProxyProvider(name string, mapping map[string]any) (types.ProxyProvider, error) {
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

	var vehicle types.Vehicle
	switch schema.Type {
	case "file":
		path := C.Path.Resolve(schema.Path)
		vehicle = resource.NewFileVehicle(path)
	case "http":
		path := C.Path.GetPathByHash("proxies", schema.URL)
		if schema.Path != "" {
			path = C.Path.Resolve(schema.Path)
			if !features.CMFA && !C.Path.IsSafePath(path) {
				return nil, fmt.Errorf("%w: %s", errSubPath, path)
			}
		}
		vehicle = resource.NewHTTPVehicle(schema.URL, path, schema.Proxy, schema.Header)
	default:
		return nil, fmt.Errorf("%w: %s", errVehicleType, schema.Type)
	}

	interval := time.Duration(uint(schema.Interval)) * time.Second
	filter := schema.Filter
	excludeFilter := schema.ExcludeFilter
	excludeType := schema.ExcludeType
	dialerProxy := schema.DialerProxy
	override := schema.Override

	return NewProxySetProvider(name, interval, filter, excludeFilter, excludeType, dialerProxy, override, vehicle, hc)
}
