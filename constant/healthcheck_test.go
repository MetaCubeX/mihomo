package constant

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewHealthCheckOption(t *testing.T) {
	option, err := NewHealthCheckOption(nil, "", nil, "")
	require.NoError(t, err)
	require.Equal(t, HealthCheckMethodHead, option.Method)

	option, err = NewHealthCheckOption(nil, "GET", []any{
		map[string]any{"name": "User-Agent", "value": "mihomo"},
		map[string]any{"Accept": []any{"text/plain", "application/json"}},
	}, "(?i)success")
	require.NoError(t, err)
	require.Equal(t, HealthCheckMethodGet, option.Method)
	require.Equal(t, []string{"mihomo"}, option.Headers["User-Agent"])
	require.Equal(t, []string{"text/plain", "application/json"}, option.Headers["Accept"])
	require.Equal(t, "(?i)success", option.ExpectedBodyMatch)
}

func TestNewHealthCheckOptionRejectsBodyMatchWithoutGet(t *testing.T) {
	_, err := NewHealthCheckOption(nil, HealthCheckMethodHead, nil, "success")
	require.Error(t, err)
}

func TestNewHealthCheckOptionRejectsInvalidMethod(t *testing.T) {
	_, err := NewHealthCheckOption(nil, "post", nil, "")
	require.Error(t, err)
}
