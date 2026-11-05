package ebpf

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDatapathELFAndSpec(t *testing.T) {
	require.True(t, bytes.HasPrefix(_DatapathBytes, []byte{'\x7f', 'E', 'L', 'F'}))
	spec, err := loadDatapath()
	require.NoError(t, err)
	for _, program := range []string{"tc_lan_ingress", "tc_dae0_ingress", "tc_dae0peer_ingress", "tproxy_sk_lookup"} {
		require.Contains(t, spec.Programs, program)
	}
	for _, mapSpec := range ABIMaps {
		require.Contains(t, spec.Maps, mapSpec.Name)
	}
}
