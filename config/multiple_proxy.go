package config

import (
	"fmt"

	"github.com/metacubex/mihomo/common/utils"
	T "github.com/metacubex/mihomo/tunnel"
)

// multipleProxyListenerType returns the inbound listener type and port for a
// multiple-proxy entry. Exactly one of MixedPort/Port/SocksPort must be set.
func multipleProxyListenerType(entry RawMultipleProxy) (ltype string, port int, err error) {
	count := 0
	for _, p := range []int{entry.MixedPort, entry.Port, entry.SocksPort} {
		if p != 0 {
			count++
		}
	}
	if count != 1 {
		return "", 0, fmt.Errorf("multiple-proxy %s: exactly one of mixed-port, port, socks-port must be set", entry.Name)
	}

	switch {
	case entry.MixedPort != 0:
		return "mixed", entry.MixedPort, nil
	case entry.Port != 0:
		return "http", entry.Port, nil
	default:
		return "socks", entry.SocksPort, nil
	}
}

// validateMultipleProxyMode checks a multiple-proxy mode. An empty mode is
// allowed and means the global mode is inherited.
func validateMultipleProxyMode(mode string) error {
	if mode == "" {
		return nil
	}
	if _, exist := T.ModeMapping[mode]; !exist {
		return fmt.Errorf("invalid multiple-proxy mode: %s", mode)
	}
	return nil
}

// collectUsedPorts returns every port occupied by the raw config, mapped to a
// human readable owner description. Ports of multiple-proxy entries are not
// included here; callers check them separately against this set.
func collectUsedPorts(cfg *RawConfig) (map[uint16]string, error) {
	used := make(map[uint16]string)

	scalars := []struct {
		port  int
		owner string
	}{
		{cfg.MixedPort, "mixed-port"},
		{cfg.Port, "port"},
		{cfg.SocksPort, "socks-port"},
		{cfg.RedirPort, "redir-port"},
		{cfg.TProxyPort, "tproxy-port"},
	}
	for _, scalar := range scalars {
		if scalar.port != 0 {
			used[uint16(scalar.port)] = scalar.owner
		}
	}

	for i, mapping := range cfg.Listeners {
		portStr, ok := mapping["port"].(string)
		if !ok {
			continue
		}
		ports, err := utils.NewUnsignedRanges[uint16](portStr)
		if err != nil {
			return nil, fmt.Errorf("listener %d: %w", i, err)
		}
		owner := fmt.Sprintf("listener %d", i)
		if name, ok := mapping["name"].(string); ok && name != "" {
			owner = fmt.Sprintf("listener %s", name)
		}
		ports.Range(func(port uint16) bool {
			used[port] = owner
			return true
		})
	}

	return used, nil
}

// multipleProxyID returns a stable identifier for a multiple-proxy entry.
func multipleProxyID(entry RawMultipleProxy, idx int) string {
	if entry.Name != "" {
		return entry.Name
	}
	return fmt.Sprintf("multiple-proxy-%d", idx)
}
