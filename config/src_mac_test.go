package config

import (
	"testing"

	"github.com/metacubex/mihomo/common/yaml"
)

func TestSourceMACTopLevelOptions(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		probe      bool
		timeout    int
		interfaces []string
		invalid    bool
	}{
		{name: "defaults", timeout: 1000},
		{name: "enabled", yaml: "src-mac-probe: true\nsrc-mac-timeout: 750\nsrc-mac-interfaces: [br-lan, eth0]\n", probe: true, timeout: 750, interfaces: []string{"br-lan", "eth0"}},
		{name: "zero", yaml: "src-mac-timeout: 0", invalid: true},
		{name: "negative", yaml: "src-mac-timeout: -1", invalid: true},
		{name: "overflow", yaml: "src-mac-timeout: 60001", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := DefaultRawConfig()
			if err := yaml.Unmarshal([]byte(tc.yaml), raw); err != nil {
				t.Fatal(err)
			}
			general, err := parseGeneral(raw)
			if tc.invalid {
				if err == nil {
					t.Fatal("invalid timeout accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if general.SrcMACProbe != tc.probe || general.SrcMACTimeout != tc.timeout || len(general.SrcMACInterfaces) != len(tc.interfaces) {
				t.Fatal("top-level options not propagated", general)
			}
		})
	}
}
