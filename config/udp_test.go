package config

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func TestUDPConfigParse(t *testing.T) {
	for _, test := range []struct {
		name    string
		input   string
		remote  bool
		mapping C.UDPMapping
	}{
		{"default", "{}", false, C.UDPEndpointIndependent},
		{"endpoint-independent", "udp-remote-resolve: true\nudp-mapping: endpoint-independent", true, C.UDPEndpointIndependent},
		{"address-dependent", "udp-remote-resolve: true\nudp-mapping: address-dependent", true, C.UDPAddressDependent},
		{"address-and-port-dependent", "udp-remote-resolve: false\nudp-mapping: address-and-port-dependent", false, C.UDPAddressAndPortDependent},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := UnmarshalRawConfig([]byte(test.input))
			require.NoError(t, err)
			general, err := parseGeneral(raw)
			require.NoError(t, err)
			require.Equal(t, test.remote, general.UDPRemoteResolve)
			require.Equal(t, test.mapping, general.UDPMapping)
		})
	}
	_, err := UnmarshalRawConfig([]byte("udp-remote-resolve: invalid"))
	require.Error(t, err)
	for _, value := range []string{`""`, "unknown", "endpoint_independent", "Endpoint-Independent", "1", "true", "[]"} {
		t.Run("invalid/"+value, func(t *testing.T) {
			_, err := UnmarshalRawConfig([]byte("udp-mapping: " + value))
			require.Error(t, err)
		})
	}
}
