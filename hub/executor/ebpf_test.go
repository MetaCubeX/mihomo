package executor

import (
	"testing"

	"github.com/metacubex/mihomo/config"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/stretchr/testify/require"
)

func TestValidateEbpfPlatform(t *testing.T) {
	cfg := &config.Config{General: &config.General{Inbound: config.Inbound{Ebpf: LC.Ebpf{Enable: true}}}}

	err := validateConfigForPlatform(cfg, "darwin")
	require.EqualError(t, err, "eBPF inbound requires Linux")
	require.NoError(t, validateConfigForPlatform(cfg, "linux"))

	cfg.General.Ebpf.Enable = false
	require.NoError(t, validateConfigForPlatform(cfg, "darwin"))
}
