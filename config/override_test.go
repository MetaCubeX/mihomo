package config

import (
	"fmt"
	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/stretchr/testify/assert"
	"os"
	"os/user"
	"runtime"
	"testing"
)

func TestMihomo_Config_Override(t *testing.T) {
	t.Run("override_existing", func(t *testing.T) {
		config_file := `
mixed-port: 7890
ipv6: true
log-level: debug
allow-lan: false
unified-delay: false
tcp-concurrent: true
external-controller: 127.0.0.1:9090
default-nameserver:
  - "223.5.5.5"
override:
  - content:
      external-controller: 0.0.0.0:9090
      allow-lan: true`
		rawCfg, err := UnmarshalRawConfig([]byte(config_file))
		assert.NoError(t, err)
		cfg, err := ParseRawConfig(rawCfg)
		assert.NoError(t, err)
		assert.Equal(t, log.DEBUG, cfg.General.LogLevel)
		assert.Equal(t, true, cfg.General.AllowLan)
		assert.Equal(t, "0.0.0.0:9090", cfg.Controller.ExternalController)
	})

	t.Run("override_zero_value_test", func(t *testing.T) {
		config_file := `
mixed-port: 7890
ipv6: true
log-level: debug
allow-lan: true
unified-delay: false
tcp-concurrent: true
external-controller: 127.0.0.1:9090
default-nameserver:
  - "223.5.5.5"
override:
  - content:
      external-controller: ""
      allow-lan: false`
		rawCfg, err := UnmarshalRawConfig([]byte(config_file))
		assert.NoError(t, err)
		cfg, err := ParseRawConfig(rawCfg)
		assert.NoError(t, err)
		assert.Equal(t, log.DEBUG, cfg.General.LogLevel)
		assert.Equal(t, false, cfg.General.AllowLan)
		assert.Equal(t, "", cfg.Controller.ExternalController)
	})

	t.Run("add_new", func(t *testing.T) {
		config_file := `
mixed-port: 7890
ipv6: true
log-level: debug
unified-delay: false
tcp-concurrent: true
override:
  - content:
      external-controller: 0.0.0.0:9090
  - content:
      allow-lan: true`
		rawCfg, err := UnmarshalRawConfig([]byte(config_file))
		assert.NoError(t, err)
		cfg, err := ParseRawConfig(rawCfg)
		assert.NoError(t, err)
		assert.Equal(t, log.DEBUG, cfg.General.LogLevel)
		assert.Equal(t, true, cfg.General.AllowLan)
		assert.Equal(t, "0.0.0.0:9090", cfg.Controller.ExternalController)
	})

	t.Run("conditions", func(t *testing.T) {
		hName, err := os.Hostname()
		assert.NoError(t, err)
		u, err := user.Current()
		assert.NoError(t, err)

		config_file := fmt.Sprintf(`
mixed-port: 7890
ipv6: true
log-level: debug
allow-lan: false
unified-delay: false
tcp-concurrent: true
external-controller: 127.0.0.1:9090
default-nameserver:
  - "223.5.5.5"
override:
  - os: %v
    arch: %v
    hostname: %v
    username: %v
    content:
      external-controller: 0.0.0.0:9090
      allow-lan: true`, runtime.GOOS, runtime.GOARCH, hName, u.Username)
		rawCfg, err := UnmarshalRawConfig([]byte(config_file))
		assert.NoError(t, err)
		cfg, err := ParseRawConfig(rawCfg)
		assert.NoError(t, err)
		assert.Equal(t, log.DEBUG, cfg.General.LogLevel)
		assert.Equal(t, true, cfg.General.AllowLan)
		assert.Equal(t, "0.0.0.0:9090", cfg.Controller.ExternalController)
	})

	t.Run("invalid_condition", func(t *testing.T) {
		config_file := `
mixed-port: 7890
log-level: debug
ipv6: true
allow-lan: false
unified-delay: false
tcp-concurrent: true
external-controller: 127.0.0.1:9090
override:
  - os: lw2eiru20f923j
    content:
      external-controller: 0.0.0.0:9090
  - arch: 32of9u8p3jrp
    content:
      allow-lan: true`
		rawCfg, err := UnmarshalRawConfig([]byte(config_file))
		assert.NoError(t, err)
		cfg, err := ParseRawConfig(rawCfg)
		assert.NoError(t, err)
		assert.Equal(t, log.DEBUG, cfg.General.LogLevel)
		assert.Equal(t, false, cfg.General.AllowLan)
		assert.Equal(t, "127.0.0.1:9090", cfg.Controller.ExternalController)
	})

	t.Run("list_insert_front", func(t *testing.T) {
		config_file := `
log-level: debug
rules:
  - DOMAIN-SUFFIX,foo.com,DIRECT
  - DOMAIN-SUFFIX,bar.org,DIRECT
  - DOMAIN-SUFFIX,bazz.io,DIRECT
override:
  - list-strategy: insert-front
    content:
      rules:
        - GEOIP,lan,DIRECT,no-resolve`
		rawCfg, err := UnmarshalRawConfig([]byte(config_file))
		assert.NoError(t, err)
		cfg, err := ParseRawConfig(rawCfg)
		assert.NoError(t, err)
		assert.Equal(t, log.DEBUG, cfg.General.LogLevel)
		assert.Equal(t, 4, len(cfg.Rules))
		assert.Equal(t, constant.GEOIP, cfg.Rules[0].RuleType())
		assert.Equal(t, false, cfg.Rules[0].ShouldResolveIP())
	})

	t.Run("list_append", func(t *testing.T) {
		config_file := `
log-level: debug
rules:
  - DOMAIN-SUFFIX,foo.com,DIRECT
  - DOMAIN-SUFFIX,bar.org,DIRECT
  - DOMAIN-SUFFIX,bazz.io,DIRECT
override:
  - list-strategy: append
    content:
      rules:
        - GEOIP,lan,DIRECT,no-resolve`
		rawCfg, err := UnmarshalRawConfig([]byte(config_file))
		assert.NoError(t, err)
		cfg, err := ParseRawConfig(rawCfg)
		assert.NoError(t, err)
		assert.Equal(t, log.DEBUG, cfg.General.LogLevel)
		assert.Equal(t, 4, len(cfg.Rules))
		assert.Equal(t, constant.GEOIP, cfg.Rules[3].RuleType())
		assert.Equal(t, false, cfg.Rules[3].ShouldResolveIP())
	})

	t.Run("list_override", func(t *testing.T) {
		config_file := `
log-level: debug
proxies: 
  - name: "DIRECT-PROXY"
    type: direct
    udp: true
  - name: "SOCKS-PROXY"
    type: socks5
    server: foo.com
    port: 443
override:
  - list-strategy: override
    content:
      proxies:
        - name: "HTTP-PROXY"
          type: http
          server: bar.org
          port: 443`
		rawCfg, err := UnmarshalRawConfig([]byte(config_file))
		assert.NoError(t, err)
		cfg, err := ParseRawConfig(rawCfg)
		assert.NoError(t, err)
		assert.Equal(t, log.DEBUG, cfg.General.LogLevel)
		assert.NotContains(t, cfg.Proxies, "DIRECT-PROXY")
		assert.NotContains(t, cfg.Proxies, "SOCKS-PROXY")
		assert.Contains(t, cfg.Proxies, "HTTP-PROXY")
		assert.Equal(t, constant.Http, cfg.Proxies["HTTP-PROXY"].Type())
	})

	t.Run("map_merge", func(t *testing.T) {
		config_file := `
log-level: debug
proxy-providers:
  provider1:
    url: "foo.com"
    type: http
    interval: 86400
    health-check: {enable: true,url: "https://www.gstatic.com/generate_204", interval: 300}
  provider2:
    url: "bar.com"
    type: http
    interval: 86400
    health-check: {enable: true,url: "https://www.gstatic.com/generate_204", interval: 300}
override:
  - content:
      proxy-providers:
        provider3:
          url: "buzz.com"
          type: http
          interval: 86400
          health-check: {enable: true,url: "https://www.google.com", interval: 300}`
		rawCfg, err := UnmarshalRawConfig([]byte(config_file))
		assert.NoError(t, err)
		cfg, err := ParseRawConfig(rawCfg)
		assert.NoError(t, err)
		assert.Equal(t, log.DEBUG, cfg.General.LogLevel)
		assert.Contains(t, cfg.Providers, "provider1")
		assert.Contains(t, cfg.Providers, "provider2")
		assert.Contains(t, cfg.Providers, "provider3")
		assert.Equal(t, "https://www.google.com", cfg.Providers["provider3"].HealthCheckURL())
	})
}
