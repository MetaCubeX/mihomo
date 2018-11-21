package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	adapters "github.com/Dreamacro/clash/adapters/outbound"
	"github.com/Dreamacro/clash/common/structure"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	R "github.com/Dreamacro/clash/rules"
	T "github.com/Dreamacro/clash/tunnel"

	yaml "gopkg.in/yaml.v2"
)

// General config
type General struct {
	Port               int          `json:"port"`
	SocksPort          int          `json:"socks-port"`
	RedirPort          int          `json:"redir-port"`
	AllowLan           bool         `json:"allow-lan"`
	Mode               T.Mode       `json:"mode"`
	LogLevel           log.LogLevel `json:"log-level"`
	ExternalController string       `json:"external-controller,omitempty"`
	Secret             string       `json:"secret,omitempty"`
}

type rawConfig struct {
	Port               int    `yaml:"port"`
	SocksPort          int    `yaml:"socks-port"`
	RedirPort          int    `yaml:"redir-port"`
	AllowLan           bool   `yaml:"allow-lan"`
	Mode               string `yaml:"mode"`
	LogLevel           string `yaml:"log-level"`
	ExternalController string `yaml:"external-controller"`
	Secret             string `yaml:"secret"`

	Proxy      []map[string]interface{} `yaml:"Proxy"`
	ProxyGroup []map[string]interface{} `yaml:"Proxy Group"`
	Rule       []string                 `yaml:"Rule"`
}

// Config is clash config manager
type Config struct {
	General *General
	Rules   []C.Rule
	Proxies map[string]C.Proxy
}

func readConfig(path string) (*rawConfig, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, err
	}
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("Configuration file %s is empty", C.Path.Config())
	}

	// config with some default value
	rawConfig := &rawConfig{
		AllowLan:   false,
		Mode:       T.Rule.String(),
		LogLevel:   log.INFO.String(),
		Rule:       []string{},
		Proxy:      []map[string]interface{}{},
		ProxyGroup: []map[string]interface{}{},
	}
	err = yaml.Unmarshal([]byte(data), &rawConfig)
	return rawConfig, err
}

// Parse config
func Parse(path string) (*Config, error) {
	config := &Config{}

	rawCfg, err := readConfig(path)
	if err != nil {
		return nil, err
	}

	general, err := parseGeneral(rawCfg)
	if err != nil {
		return nil, err
	}
	config.General = general

	proxies, err := parseProxies(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Proxies = proxies

	rules, err := parseRules(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Rules = rules

	return config, nil
}

func parseGeneral(cfg *rawConfig) (*General, error) {
	port := cfg.Port
	socksPort := cfg.SocksPort
	redirPort := cfg.RedirPort
	allowLan := cfg.AllowLan
	logLevelString := cfg.LogLevel
	modeString := cfg.Mode
	externalController := cfg.ExternalController
	secret := cfg.Secret

	mode, exist := T.ModeMapping[modeString]
	if !exist {
		return nil, fmt.Errorf("General.mode value invalid")
	}

	logLevel, exist := log.LogLevelMapping[logLevelString]
	if !exist {
		return nil, fmt.Errorf("General.log-level value invalid")
	}

	general := &General{
		Port:               port,
		SocksPort:          socksPort,
		RedirPort:          redirPort,
		AllowLan:           allowLan,
		Mode:               mode,
		LogLevel:           logLevel,
		ExternalController: externalController,
		Secret:             secret,
	}
	return general, nil
}

func parseProxies(cfg *rawConfig) (map[string]C.Proxy, error) {
	proxies := make(map[string]C.Proxy)
	proxiesConfig := cfg.Proxy
	groupsConfig := cfg.ProxyGroup

	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true})

	proxies["DIRECT"] = adapters.NewDirect()
	proxies["REJECT"] = adapters.NewReject()

	// parse proxy
	for idx, mapping := range proxiesConfig {
		proxyType, existType := mapping["type"].(string)
		if !existType {
			return nil, fmt.Errorf("Proxy %d missing type", idx)
		}

		var proxy C.Proxy
		var err error
		switch proxyType {
		case "ss":
			ssOption := &adapters.ShadowSocksOption{}
			err = decoder.Decode(mapping, ssOption)
			if err != nil {
				break
			}
			proxy, err = adapters.NewShadowSocks(*ssOption)
		case "socks5":
			socksOption := &adapters.Socks5Option{}
			err = decoder.Decode(mapping, socksOption)
			if err != nil {
				break
			}
			proxy = adapters.NewSocks5(*socksOption)
		case "vmess":
			vmessOption := &adapters.VmessOption{}
			err = decoder.Decode(mapping, vmessOption)
			if err != nil {
				break
			}
			proxy, err = adapters.NewVmess(*vmessOption)
		default:
			return nil, fmt.Errorf("Unsupport proxy type: %s", proxyType)
		}

		if err != nil {
			return nil, fmt.Errorf("Proxy [%d]: %s", idx, err.Error())
		}

		if _, exist := proxies[proxy.Name()]; exist {
			return nil, fmt.Errorf("Proxy %s is the duplicate name", proxy.Name())
		}
		proxies[proxy.Name()] = proxy
	}

	// parse proxy group
	for idx, mapping := range groupsConfig {
		groupType, existType := mapping["type"].(string)
		groupName, existName := mapping["name"].(string)
		if !existType && existName {
			return nil, fmt.Errorf("ProxyGroup %d: missing type or name", idx)
		}

		if _, exist := proxies[groupName]; exist {
			return nil, fmt.Errorf("ProxyGroup %s: the duplicate name", groupName)
		}
		var group C.Proxy
		var err error
		switch groupType {
		case "url-test":
			urlTestOption := &adapters.URLTestOption{}
			err = decoder.Decode(mapping, urlTestOption)
			if err != nil {
				break
			}

			ps, err := getProxies(proxies, urlTestOption.Proxies)
			if err != nil {
				return nil, fmt.Errorf("ProxyGroup %s: %s", groupName, err.Error())
			}
			group, err = adapters.NewURLTest(*urlTestOption, ps)
		case "select":
			selectorOption := &adapters.SelectorOption{}
			err = decoder.Decode(mapping, selectorOption)
			if err != nil {
				break
			}

			ps, err := getProxies(proxies, selectorOption.Proxies)
			if err != nil {
				return nil, fmt.Errorf("ProxyGroup %s: %s", groupName, err.Error())
			}
			group, err = adapters.NewSelector(selectorOption.Name, ps)
		case "fallback":
			fallbackOption := &adapters.FallbackOption{}
			err = decoder.Decode(mapping, fallbackOption)
			if err != nil {
				break
			}

			ps, err := getProxies(proxies, fallbackOption.Proxies)
			if err != nil {
				return nil, fmt.Errorf("ProxyGroup %s: %s", groupName, err.Error())
			}
			group, err = adapters.NewFallback(*fallbackOption, ps)
		}
		if err != nil {
			return nil, fmt.Errorf("Proxy %s: %s", groupName, err.Error())
		}
		proxies[groupName] = group
	}

	var ps []C.Proxy
	for _, v := range proxies {
		ps = append(ps, v)
	}

	proxies["GLOBAL"], _ = adapters.NewSelector("GLOBAL", ps)

	// close old goroutine
	for _, proxy := range proxies {
		switch raw := proxy.(type) {
		case *adapters.URLTest:
			raw.Close()
		case *adapters.Fallback:
			raw.Close()
		}
	}
	return proxies, nil
}

func parseRules(cfg *rawConfig) ([]C.Rule, error) {
	rules := []C.Rule{}

	rulesConfig := cfg.Rule
	// parse rules
	for _, line := range rulesConfig {
		rule := strings.Split(line, ",")
		if len(rule) < 3 {
			continue
		}
		rule = trimArr(rule)
		switch rule[0] {
		case "DOMAIN":
			rules = append(rules, R.NewDomain(rule[1], rule[2]))
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

	return rules, nil
}
