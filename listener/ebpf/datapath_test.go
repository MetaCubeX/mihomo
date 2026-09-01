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
	require.Contains(t, spec.Programs, "tc_ingress")
	for _, mapSpec := range ABIMaps {
		require.Contains(t, spec.Maps, mapSpec.Name)
	}
}
