package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Dreamacro/clash/adapters/remote"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/observable"
	R "github.com/Dreamacro/clash/rules"

	"gopkg.in/ini.v1"
)

var (
	config *Config
	once   sync.Once
)

// Config is clash config manager
type Config struct {
	general    *General
	rules      []C.Rule
	proxies    map[string]C.Proxy
	lastUpdate time.Time

	event      chan<- interface{}
	errCh      chan interface{}
	observable *observable.Observable
}

// Event is event of clash config
type Event struct {
	Type    string
	Payload interface{}
}

// Subscribe config stream
func (c *Config) Subscribe() observable.Subscription {
	sub, _ := c.observable.Subscribe()
	return sub
}

// Report return a channel for collecting error message
func (c *Config) Report() chan<- interface{} {
	return c.errCh
}

func (c *Config) readConfig() (*ini.File, error) {
	if _, err := os.Stat(C.ConfigPath); os.IsNotExist(err) {
		return nil, err
	}
	return ini.LoadSources(
		ini.LoadOptions{AllowBooleanKeys: true},
		C.ConfigPath,
	)
}

// Parse config
func (c *Config) Parse() error {
	cfg, err := c.readConfig()
	if err != nil {
		return err
	}

	if err := c.parseGeneral(cfg); err != nil {
		return err
	}

	if err := c.parseProxies(cfg); err != nil {
		return err
	}

	return c.parseRules(cfg)
}

// Proxies return proxies of clash
func (c *Config) Proxies() map[string]C.Proxy {
	return c.proxies
}

// Rules return rules of clash
func (c *Config) Rules() []C.Rule {
	return c.rules
}

// SetMode change mode of clash
func (c *Config) SetMode(mode Mode) {
	c.general.Mode = mode
	c.event <- &Event{Type: "mode", Payload: mode}
}

// General return clash general config
func (c *Config) General() General {
	return *c.general
}

// UpdateRules is a function for hot reload rules
func (c *Config) UpdateRules() error {
	cfg, err := c.readConfig()
	if err != nil {
		return err
	}

	return c.parseRules(cfg)
}

func (c *Config) parseGeneral(cfg *ini.File) error {
	general := cfg.Section("General")

	port := general.Key("port").RangeInt(C.DefalutHTTPPort, 1, 65535)
	socksPort := general.Key("socks-port").RangeInt(C.DefalutSOCKSPort, 1, 65535)
	allowLan := general.Key("allow-lan").MustBool()
	logLevelString := general.Key("log-level").MustString(C.INFO.String())
	modeString := general.Key("mode").MustString(Rule.String())

	mode, exist := ModeMapping[modeString]
	if !exist {
		return fmt.Errorf("General.mode value invalid")
	}

	logLevel, exist := C.LogLevelMapping[logLevelString]
	if !exist {
		return fmt.Errorf("General.log-level value invalid")
	}

	c.general = &General{
		Base: &Base{
			Port:       &port,
			SocketPort: &socksPort,
			AllowLan:   &allowLan,
		},
		Mode:     mode,
		LogLevel: logLevel,
	}

	if restAddr := general.Key("external-controller").String(); restAddr != "" {
		c.event <- &Event{Type: "external-controller", Payload: restAddr}
	}

	c.UpdateGeneral(*c.general)
	return nil
}

// UpdateGeneral dispatch update event
func (c *Config) UpdateGeneral(general General) {
	c.event <- &Event{Type: "base", Payload: *general.Base}
	c.event <- &Event{Type: "mode", Payload: general.Mode}
	c.event <- &Event{Type: "log-level", Payload: general.LogLevel}
}

func (c *Config) parseProxies(cfg *ini.File) error {
	proxies := make(map[string]C.Proxy)
	proxiesConfig := cfg.Section("Proxy")
	groupsConfig := cfg.Section("Proxy Group")

	// parse proxy
	for _, key := range proxiesConfig.Keys() {
		proxy := key.Strings(",")
		if len(proxy) == 0 {
			continue
		}
		switch proxy[0] {
		// ss, server, port, cipter, password
		case "ss":
			if len(proxy) < 5 {
				continue
			}
			ssURL := fmt.Sprintf("ss://%s:%s@%s:%s", proxy[3], proxy[4], proxy[1], proxy[2])
			ss, err := adapters.NewShadowSocks(key.Name(), ssURL)
			if err != nil {
				return err
			}
			proxies[key.Name()] = ss
		}
	}

	// parse proxy group
	for _, key := range groupsConfig.Keys() {
		rule := strings.Split(key.Value(), ",")
		rule = trimArr(rule)
		switch rule[0] {
		case "url-test":
			if len(rule) < 4 {
				return fmt.Errorf("URLTest need more than 4 param")
			}
			proxyNames := rule[1 : len(rule)-2]
			delay, _ := strconv.Atoi(rule[len(rule)-1])
			url := rule[len(rule)-2]
			var ps []C.Proxy
			for _, name := range proxyNames {
				if p, ok := proxies[name]; ok {
					ps = append(ps, p)
				}
			}

			adapter, err := adapters.NewURLTest(key.Name(), ps, url, time.Duration(delay)*time.Second)
			if err != nil {
				return fmt.Errorf("Config error: %s", err.Error())
			}
			proxies[key.Name()] = adapter
		case "select":
			if len(rule) < 3 {
				return fmt.Errorf("Selector need more than 3 param")
			}
			proxyNames := rule[1:]
			selectProxy := make(map[string]C.Proxy)
			for _, name := range proxyNames {
				proxy, exist := proxies[name]
				if !exist {
					return fmt.Errorf("Proxy %s not exist", name)
				}
				selectProxy[name] = proxy
			}
			selector, err := adapters.NewSelector(key.Name(), selectProxy)
			if err != nil {
				return fmt.Errorf("Selector create error: %s", err.Error())
			}
			proxies[key.Name()] = selector
		}
	}

	// init proxy
	proxies["DIRECT"] = adapters.NewDirect()
	proxies["REJECT"] = adapters.NewReject()

	c.proxies = proxies
	c.event <- &Event{Type: "proxies", Payload: proxies}
	return nil
}

func (c *Config) parseRules(cfg *ini.File) error {
	rules := []C.Rule{}

	rulesConfig := cfg.Section("Rule")
	// parse rules
	for _, key := range rulesConfig.Keys() {
		rule := strings.Split(key.Name(), ",")
		if len(rule) < 3 {
			continue
		}
		rule = trimArr(rule)
		switch rule[0] {
		case "DOMAIN-SUFFIX":
			rules = append(rules, R.NewDomainSuffix(rule[1], rule[2]))
		case "DOMAIN-KEYWORD":
			rules = append(rules, R.NewDomainKeyword(rule[1], rule[2]))
		case "GEOIP":
			rules = append(rules, R.NewGEOIP(rule[1], rule[2]))
		case "IP-CIDR", "IP-CIDR6":
			rules = append(rules, R.NewIPCIDR(rule[1], rule[2]))
		case "FINAL":
			rules = append(rules, R.NewFinal(rule[2]))
		}
	}

	c.rules = rules
	c.event <- &Event{Type: "rules", Payload: rules}
	return nil
}

func (c *Config) handleErrorMessage() {
	for elm := range c.errCh {
		event := elm.(Event)
		switch event.Type {
		case "base":
			c.general.Base = event.Payload.(*Base)
		}
	}
}

func newConfig() *Config {
	event := make(chan interface{})
	config := &Config{
		general:    &General{},
		proxies:    make(map[string]C.Proxy),
		rules:      []C.Rule{},
		lastUpdate: time.Now(),

		event:      event,
		observable: observable.NewObservable(event),
	}
	go config.handleErrorMessage()
	return config
}

func Instance() *Config {
	once.Do(func() {
		config = newConfig()
	})
	return config
}
