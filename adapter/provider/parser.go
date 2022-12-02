package provider

import (
	"errors"
	"fmt"
	"github.com/Dreamacro/clash/component/resource"
	"time"

	"github.com/Dreamacro/clash/common/structure"
	C "github.com/Dreamacro/clash/constant"
	types "github.com/Dreamacro/clash/constant/provider"
)

var errVehicleType = errors.New("unsupport vehicle type")

type healthCheckSchema struct {
	Enable   bool   `provider:"enable"`
	URL      string `provider:"url"`
	Interval int    `provider:"interval"`
	Lazy     bool   `provider:"lazy,omitempty"`
}

type proxyProviderSchema struct {
	Type          string            `provider:"type"`
	Path          string            `provider:"path"`
	URL           string            `provider:"url,omitempty"`
	Interval      int               `provider:"interval,omitempty"`
	Filter        string            `provider:"filter,omitempty"`
	ExcludeFilter string            `provider:"exclude-filter,omitempty"`
	HealthCheck   healthCheckSchema `provider:"health-check,omitempty"`
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

	var hcInterval uint
	if schema.HealthCheck.Enable {
		hcInterval = uint(schema.HealthCheck.Interval)
	}
	hc := NewHealthCheck([]C.Proxy{}, schema.HealthCheck.URL, hcInterval, schema.HealthCheck.Lazy)

	path := C.Path.Resolve(schema.Path)

	var vehicle types.Vehicle
	switch schema.Type {
	case "file":
		vehicle = resource.NewFileVehicle(path)
	case "http":
		vehicle = resource.NewHTTPVehicle(schema.URL, path)
	default:
		return nil, fmt.Errorf("%w: %s", errVehicleType, schema.Type)
	}

	interval := time.Duration(uint(schema.Interval)) * time.Second
	filter := schema.Filter
	excludeFilter := schema.ExcludeFilter
	return NewProxySetProvider(name, interval, filter, excludeFilter, vehicle, hc)
}
