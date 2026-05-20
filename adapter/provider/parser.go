package provider

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
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
	Type          string           `provider:"type"`
	Path          string           `provider:"path,omitempty"`
	URL           string           `provider:"url,omitempty"`
	Proxy         string           `provider:"proxy,omitempty"`
	Command       []string         `provider:"command,omitempty"`
	Timeout       int              `provider:"timeout,omitempty"`
	Interval      int              `provider:"interval,omitempty"`
	Filter        string           `provider:"filter,omitempty"`
	ExcludeFilter string           `provider:"exclude-filter,omitempty"`
	ExcludeType   string           `provider:"exclude-type,omitempty"`
	DialerProxy   string           `provider:"dialer-proxy,omitempty"`
	SizeLimit     int64            `provider:"size-limit,omitempty"`
	Payload       []map[string]any `provider:"payload,omitempty"`

	HealthCheck healthCheckSchema   `provider:"health-check,omitempty"`
	Override    overrideSchema      `provider:"override,omitempty"`
	Header      map[string][]string `provider:"header,omitempty"`
}

func ParseProxyProvider(name string, mapping map[string]any, tunnel C.Tunnel) (P.ProxyProvider, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})

	if schemaType, ok := mapping["type"].(string); ok && schemaType == "exec" {
		if err := validateExecCommandRaw(mapping); err != nil {
			return nil, err
		}
	}

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

	parser, err := NewProxiesParser(name, tunnel, schema.Filter, schema.ExcludeFilter, schema.ExcludeType, schema.DialerProxy, schema.Override)
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
	case "exec":
		if err := validateExecCommand(schema.Command); err != nil {
			return nil, err
		}
		path := C.Path.GetPathByHash("proxies", "exec:"+strings.Join(schema.Command, "\x00"))
		if schema.Path != "" {
			path = C.Path.Resolve(schema.Path)
			if !C.Path.IsSafePath(path) {
				return nil, C.Path.ErrNotSafePath(path)
			}
		}
		timeout := resource.DefaultHttpTimeout
		if schema.Timeout > 0 {
			timeout = time.Duration(uint(schema.Timeout)) * time.Second
		}
		vehicle = resource.NewExecVehicle(schema.Command, path, timeout, schema.SizeLimit)
	case "inline":
		return NewInlineProvider(name, schema.Payload, parser, hc)
	default:
		return nil, fmt.Errorf("%w: %s", errVehicleType, schema.Type)
	}

	interval := time.Duration(uint(schema.Interval)) * time.Second

	return NewProxySetProvider(name, interval, schema.Payload, parser, vehicle, hc)
}

func validateExecCommandRaw(mapping map[string]any) error {
	rawCommand, ok := mapping["command"]
	if !ok {
		return errors.New("exec provider command is required")
	}
	switch value := rawCommand.(type) {
	case []string:
	case []any:
		for _, item := range value {
			if _, ok := item.(string); !ok {
				return errors.New("exec provider command must be an array of strings")
			}
		}
	default:
		return errors.New("exec provider command must be an array of strings")
	}
	return nil
}

func validateExecCommand(command []string) error {
	if len(command) == 0 {
		return errors.New("exec provider command is required")
	}
	if !filepath.IsAbs(command[0]) {
		return errors.New("exec provider command executable must be an absolute path")
	}
	return nil
}
