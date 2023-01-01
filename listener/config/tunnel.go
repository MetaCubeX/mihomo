package config

import (
	"fmt"
	"net"
	"strings"

	"github.com/samber/lo"
)

type tunnel struct {
	Network []string `yaml:"network"`
	Address string   `yaml:"address"`
	Target  string   `yaml:"target"`
	Proxy   string   `yaml:"proxy"`
}

type Tunnel tunnel

// UnmarshalYAML implements yaml.Unmarshaler
func (t *Tunnel) UnmarshalYAML(unmarshal func(any) error) error {
	var tp string
	if err := unmarshal(&tp); err != nil {
		var inner tunnel
		if err := unmarshal(&inner); err != nil {
			return err
		}

		*t = Tunnel(inner)
		return nil
	}

	// parse udp/tcp,address,target,proxy
	parts := lo.Map(strings.Split(tp, ","), func(s string, _ int) string {
		return strings.TrimSpace(s)
	})
	if len(parts) != 3 && len(parts) != 4 {
		return fmt.Errorf("invalid tunnel config %s", tp)
	}
	network := strings.Split(parts[0], "/")

	// validate network
	for _, n := range network {
		switch n {
		case "tcp", "udp":
		default:
			return fmt.Errorf("invalid tunnel network %s", n)
		}
	}

	// validate address and target
	address := parts[1]
	target := parts[2]
	for _, addr := range []string{address, target} {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("invalid tunnel target or address %s", addr)
		}
	}

	*t = Tunnel(tunnel{
		Network: network,
		Address: address,
		Target:  target,
	})
	if len(parts) == 4 {
		t.Proxy = parts[3]
	}
	return nil
}
