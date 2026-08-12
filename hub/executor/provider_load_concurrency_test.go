package executor

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProviderLoadConcurrencyConfig(t *testing.T) {
	config, err := ParseWithBytes([]byte("provider-load-concurrency: 1\n"))
	require.NoError(t, err)
	require.Equal(t, 1, config.General.ProviderLoadConcurrency)
}

func TestProviderLoadConcurrencyDefaultsToArchitectureValue(t *testing.T) {
	config, err := ParseWithBytes([]byte(""))
	require.NoError(t, err)
	require.Zero(t, config.General.ProviderLoadConcurrency)
}
