package adapter

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func TestParseWARPProxy(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":       "warp-test",
		"type":       "warp",
		"mode":       "masque",
		"accept-tos": true,
	})
	require.NoError(t, err)
	defer proxy.Close()
	require.Equal(t, C.Warp, proxy.Type())
}
