package outbound

import (
	"testing"

	"github.com/metacubex/mihomo/transport/x365"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewX365Defaults(t *testing.T) {
	option := X365Option{
		Name:       "x365",
		Server:     "127.0.0.1",
		Port:       443,
		UUID:       "c5f1a574-20a8-4f06-8880-2ae7a4af2f7e",
		ServerName: "example.com",
		XHTTPOpts:  XHTTPOptions{Path: "/"},
	}

	t.Run("default", func(t *testing.T) {
		proxy, err := NewX365(option)
		require.NoError(t, err)
		defer proxy.Close()

		assert.Equal(t, x365.UserAgent, proxy.option.XHTTPOpts.Headers["User-Agent"])
		assert.Equal(t, "stream-one", proxy.option.XHTTPOpts.Mode)
		assert.False(t, proxy.SupportUDP())
		assert.False(t, proxy.SupportUOT())
	})

	t.Run("custom user agent", func(t *testing.T) {
		custom := option
		custom.XHTTPOpts.Headers = map[string]string{"user-agent": "custom"}
		proxy, err := NewX365(custom)
		require.NoError(t, err)
		defer proxy.Close()

		assert.Equal(t, map[string]string{"user-agent": "custom"}, proxy.option.XHTTPOpts.Headers)
	})

	t.Run("mode", func(t *testing.T) {
		for _, mode := range []string{"auto", "stream-one"} {
			custom := option
			custom.XHTTPOpts.Mode = mode
			proxy, err := NewX365(custom)
			require.NoError(t, err, mode)
			assert.Equal(t, "stream-one", proxy.option.XHTTPOpts.Mode, mode)
			_ = proxy.Close()
		}
		for _, mode := range []string{"stream-up", "packet-up"} {
			custom := option
			custom.XHTTPOpts.Mode = mode
			_, err := NewX365(custom)
			assert.Error(t, err, mode)
		}

		custom := option
		custom.XHTTPOpts.DownloadSettings = &XHTTPDownloadSettings{}
		_, err := NewX365(custom)
		assert.Error(t, err, "download-settings needs a separate download request, which x365 does not have")
	})
}
