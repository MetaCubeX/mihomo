package ebpf

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDatapathCloseIsIdempotent(t *testing.T) {
	var datapath Datapath
	require.NoError(t, datapath.Close())
	require.NoError(t, datapath.Close())
	require.NoError(t, (*Datapath)(nil).Close())
}

func TestLoadDatapathIntegration(t *testing.T) {
	if os.Getenv("MIHOMO_EBPF_INTEGRATION") != "1" {
		t.Skip("set MIHOMO_EBPF_INTEGRATION=1 to load the datapath into this Linux kernel")
	}
	caps, err := ProbeCapabilities()
	require.NoError(t, err)
	require.True(t, caps.BPF && caps.TC && caps.CgroupV2 && caps.SKLookup)

	datapath, err := LoadDatapath()
	require.NoError(t, err)
	require.NotNil(t, datapath.Program("tc_ingress"))
	for _, mapSpec := range ABIMaps {
		require.NotNilf(t, datapath.Map(mapSpec.Name), "map %s", mapSpec.Name)
	}
	require.NoError(t, datapath.Close())
	require.NoError(t, datapath.Close())
}

func TestUnsupportedPlatformContract(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux has a real capability probe")
	}
	_, err := ProbeCapabilities()
	require.ErrorIs(t, err, ErrUnsupported)
	require.EqualError(t, err, "eBPF inbound requires Linux")
}
