package adapter_test

import (
	"testing"

	"github.com/metacubex/mihomo/adapter"

	"github.com/stretchr/testify/require"
)

// Do not import config: parsing proxy DNS must work without its init functions.
func TestParseProxyWireGuardDNSWithoutConfig(t *testing.T) {
	for _, testCase := range []struct {
		name string
		dns  string
		err  string
	}{
		{name: "valid", dns: "1.1.1.1"},
		{name: "invalid", dns: "foo://1.1.1.1", err: "unsupport scheme"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			proxy, err := adapter.ParseProxy(map[string]any{
				"name":               "wg-repro",
				"type":               "wireguard",
				"server":             "192.0.2.1",
				"port":               2480,
				"ip":                 "172.16.0.2",
				"private-key":        "eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=",
				"public-key":         "Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=",
				"remote-dns-resolve": true,
				"dns":                []string{testCase.dns},
			})
			if testCase.err != "" {
				require.ErrorContains(t, err, testCase.err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, proxy)
			t.Cleanup(func() { require.NoError(t, proxy.Close()) })
		})
	}
}
