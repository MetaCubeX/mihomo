package adapter_test

import (
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/convert"
	"github.com/stretchr/testify/require"
)

// Regression test for MetaCubeX/mihomo#2555: the output of
// convert.ConvertsV2Ray must be decodable by adapter.ParseProxy.
func TestParseProxy_AcceptsShareLinkH2Transport(t *testing.T) {
	const shareLink = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&type=http&host=cdn.example.com&path=%2Fgrpc#vless-h2"

	proxies, err := convert.ConvertsV2Ray([]byte(shareLink))
	require.NoError(t, err)
	require.Len(t, proxies, 1)

	_, err = adapter.ParseProxy(proxies[0])
	require.NoError(t, err)
}
