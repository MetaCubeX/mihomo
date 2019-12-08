package provider

import (
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/Dreamacro/clash/adapters/outbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"

	"gopkg.in/yaml.v2"
)

const (
	ReservedName = "default"

	fileMode = 0666
)

// Provider Type
const (
	Proxy ProviderType = iota
	Rule
)

// ProviderType defined
type ProviderType int

func (pt ProviderType) String() string {
	switch pt {
	case Proxy:
		return "Proxy"
	case Rule:
		return "Rule"
	default:
		return "Unknown"
	}
}

// Provider interface
type Provider interface {
	Name() string
	VehicleType() VehicleType
	Type() ProviderType
	Initial() error
	Reload() error
	Destroy() error
}

// ProxyProvider interface
type ProxyProvider interface {
	Provider
	Proxies() []C.Proxy
}

type ProxySchema struct {
	Proxies []map[string]interface{} `yaml:"proxies"`
}

type ProxySetProvider struct {
	name              string
	vehicle           Vehicle
	hash              [16]byte
	proxies           []C.Proxy
	healthCheck       *healthCheck
	healthCheckOption *HealthCheckOption
	ticker            *time.Ticker

	// mux for avoiding creating new goroutines when pulling
	mux sync.Mutex
}

func (pp *ProxySetProvider) Name() string {
	return pp.name
}

func (pp *ProxySetProvider) Reload() error {
	return nil
}

func (pp *ProxySetProvider) Destroy() error {
	pp.mux.Lock()
	defer pp.mux.Unlock()
	if pp.healthCheck != nil {
		pp.healthCheck.close()
		pp.healthCheck = nil
	}

	if pp.ticker != nil {
		pp.ticker.Stop()
	}

	return nil
}

func (pp *ProxySetProvider) Initial() error {
	var buf []byte
	var err error
	if _, err := os.Stat(pp.vehicle.Path()); err == nil {
		buf, err = ioutil.ReadFile(pp.vehicle.Path())
	} else {
		buf, err = pp.vehicle.Read()
	}

	if err != nil {
		return err
	}

	proxies, err := pp.parse(buf)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(pp.vehicle.Path(), buf, fileMode); err != nil {
		return err
	}

	pp.hash = md5.Sum(buf)
	pp.setProxies(proxies)

	// pull proxies automatically
	if pp.ticker != nil {
		go pp.pullLoop()
	}

	return nil
}

func (pp *ProxySetProvider) VehicleType() VehicleType {
	return pp.vehicle.Type()
}

func (pp *ProxySetProvider) Type() ProviderType {
	return Proxy
}

func (pp *ProxySetProvider) Proxies() []C.Proxy {
	return pp.proxies
}

func (pp *ProxySetProvider) pullLoop() {
	for range pp.ticker.C {
		if err := pp.pull(); err != nil {
			log.Warnln("[Provider] %s pull error: %s", pp.Name(), err.Error())
		}
	}
}

func (pp *ProxySetProvider) pull() error {
	buf, err := pp.vehicle.Read()
	if err != nil {
		return err
	}

	hash := md5.Sum(buf)
	if bytes.Equal(pp.hash[:], hash[:]) {
		log.Debugln("[Provider] %s's proxies doesn't change", pp.Name())
		return nil
	}

	proxies, err := pp.parse(buf)
	if err != nil {
		return err
	}
	log.Infoln("[Provider] %s's proxies update", pp.Name())

	if err := ioutil.WriteFile(pp.vehicle.Path(), buf, fileMode); err != nil {
		return err
	}

	pp.hash = hash
	pp.setProxies(proxies)

	return nil
}

func (pp *ProxySetProvider) parse(buf []byte) ([]C.Proxy, error) {
	schema := &ProxySchema{}

	if err := yaml.Unmarshal(buf, schema); err != nil {
		return nil, err
	}

	if schema.Proxies == nil {
		return nil, errors.New("File must have a `proxies` field")
	}

	proxies := []C.Proxy{}
	for idx, mapping := range schema.Proxies {
		proxy, err := outbound.ParseProxy(mapping)
		if err != nil {
			return nil, fmt.Errorf("Proxy %d error: %w", idx, err)
		}
		proxies = append(proxies, proxy)
	}

	return proxies, nil
}

func (pp *ProxySetProvider) setProxies(proxies []C.Proxy) {
	pp.proxies = proxies
	if pp.healthCheckOption != nil {
		pp.mux.Lock()
		if pp.healthCheck != nil {
			pp.healthCheck.close()
			pp.healthCheck = newHealthCheck(proxies, pp.healthCheckOption.URL, pp.healthCheckOption.Interval)
			go pp.healthCheck.process()
		}
		pp.mux.Unlock()
	}
}

func NewProxySetProvider(name string, interval time.Duration, vehicle Vehicle, option *HealthCheckOption) *ProxySetProvider {
	var ticker *time.Ticker
	if interval != 0 {
		ticker = time.NewTicker(interval)
	}

	return &ProxySetProvider{
		name:              name,
		vehicle:           vehicle,
		proxies:           []C.Proxy{},
		healthCheckOption: option,
		ticker:            ticker,
	}
}

type CompatibleProvier struct {
	name        string
	healthCheck *healthCheck
	proxies     []C.Proxy
}

func (cp *CompatibleProvier) Name() string {
	return cp.name
}

func (cp *CompatibleProvier) Reload() error {
	return nil
}

func (cp *CompatibleProvier) Destroy() error {
	if cp.healthCheck != nil {
		cp.healthCheck.close()
	}
	return nil
}

func (cp *CompatibleProvier) Initial() error {
	if cp.healthCheck != nil {
		go cp.healthCheck.process()
	}
	return nil
}

func (cp *CompatibleProvier) VehicleType() VehicleType {
	return Compatible
}

func (cp *CompatibleProvier) Type() ProviderType {
	return Proxy
}

func (cp *CompatibleProvier) Proxies() []C.Proxy {
	return cp.proxies
}

func NewCompatibleProvier(name string, proxies []C.Proxy, option *HealthCheckOption) (*CompatibleProvier, error) {
	if len(proxies) == 0 {
		return nil, errors.New("Provider need one proxy at least")
	}

	var hc *healthCheck
	if option != nil {
		if _, err := url.Parse(option.URL); err != nil {
			return nil, fmt.Errorf("URL format error: %w", err)
		}
		hc = newHealthCheck(proxies, option.URL, option.Interval)
	}

	return &CompatibleProvier{
		name:        name,
		proxies:     proxies,
		healthCheck: hc,
	}, nil
}
