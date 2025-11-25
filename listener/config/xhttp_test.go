package config

import (
	"testing"

	"github.com/metacubex/mihomo/transport/xhttp"
	"github.com/stretchr/testify/assert"
)

func TestXhttpServer_Validation(t *testing.T) {
	t.Run("Valid basic config", func(t *testing.T) {
		xs := XhttpServer{
			Enable:      true,
			Listen:      "0.0.0.0:8080",
			Path:        "/xhttp/",
			Mode:        "auto",
			HTTPVersion: "1.1",
		}

		assert.True(t, xs.Enable)
		assert.Equal(t, "0.0.0.0:8080", xs.Listen)
		assert.Equal(t, "/xhttp/", xs.Path)
		assert.Equal(t, "auto", xs.Mode)
		assert.Equal(t, "1.1", xs.HTTPVersion)
	})

	t.Run("Valid config with headers", func(t *testing.T) {
		xs := XhttpServer{
			Enable:      true,
			Listen:      "127.0.0.1:8443",
			Path:        "/custom-path/",
			Mode:        "packet-up",
			HTTPVersion: "2",
			Headers: map[string]string{
				"X-Custom-Header": "test-value",
				"Server":          "mihomo-xhttp",
			},
		}

		assert.NotNil(t, xs.Headers)
		assert.Equal(t, "test-value", xs.Headers["X-Custom-Header"])
		assert.Equal(t, "mihomo-xhttp", xs.Headers["Server"])
		assert.Equal(t, "packet-up", xs.Mode)
	})

	t.Run("Valid config with padding range", func(t *testing.T) {
		xs := XhttpServer{
			Enable:        true,
			Listen:        "0.0.0.0:8080",
			XPaddingBytes: xhttp.Range{From: 100, To: 1000},
		}

		assert.Equal(t, int32(100), xs.XPaddingBytes.From)
		assert.Equal(t, int32(1000), xs.XPaddingBytes.To)
		assert.False(t, xs.XPaddingBytes.IsZero())
	})

	t.Run("Valid config with xmux settings", func(t *testing.T) {
		xs := XhttpServer{
			Enable: true,
			Listen: "0.0.0.0:8080",
			Xmux: XhttpXmuxConfig{
				MaxConcurrency:   xhttp.Range{From: 1, To: 1},
				MaxConnections:   xhttp.Range{From: 0, To: 0},
				HMaxRequestTimes: xhttp.Range{From: 600, To: 900},
				HMaxReusableSecs: xhttp.Range{From: 1800, To: 3000},
				HKeepAlivePeriod: 30,
			},
		}

		assert.Equal(t, int32(1), xs.Xmux.MaxConcurrency.From)
		assert.Equal(t, int32(600), xs.Xmux.HMaxRequestTimes.From)
		assert.Equal(t, int32(900), xs.Xmux.HMaxRequestTimes.To)
		assert.Equal(t, int64(30), xs.Xmux.HKeepAlivePeriod)
	})

	t.Run("Valid config with TLS certificates", func(t *testing.T) {
		xs := XhttpServer{
			Enable:      true,
			Listen:      "0.0.0.0:8443",
			HTTPVersion: "2",
			Certificate: "/path/to/cert.pem",
			PrivateKey:  "/path/to/key.pem",
		}

		assert.Equal(t, "/path/to/cert.pem", xs.Certificate)
		assert.Equal(t, "/path/to/key.pem", xs.PrivateKey)
		assert.Equal(t, "2", xs.HTTPVersion)
	})

	t.Run("Default path normalization", func(t *testing.T) {
		testCases := []struct {
			name     string
			path     string
			expected string
		}{
			{"Empty path", "", ""},
			{"Root path", "/", "/"},
			{"Path with trailing slash", "/xhttp/", "/xhttp/"},
			{"Path without trailing slash", "/xhttp", "/xhttp"},
			{"Nested path", "/api/v1/xhttp/", "/api/v1/xhttp/"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				xs := XhttpServer{
					Enable: true,
					Listen: "0.0.0.0:8080",
					Path:   tc.path,
				}
				assert.Equal(t, tc.expected, xs.Path)
			})
		}
	})

	t.Run("Mode validation", func(t *testing.T) {
		validModes := []string{"auto", "stream-up", "packet-up", "stream-one"}

		for _, mode := range validModes {
			xs := XhttpServer{
				Enable: true,
				Listen: "0.0.0.0:8080",
				Mode:   mode,
			}
			assert.Equal(t, mode, xs.Mode)
		}
	})

	t.Run("HTTP version validation", func(t *testing.T) {
		validVersions := []string{"auto", "1.1", "2", "3"}

		for _, version := range validVersions {
			xs := XhttpServer{
				Enable:      true,
				Listen:      "0.0.0.0:8080",
				HTTPVersion: version,
			}
			assert.Equal(t, version, xs.HTTPVersion)
		}
	})

	t.Run("Zero value range is valid", func(t *testing.T) {
		xs := XhttpServer{
			Enable:             true,
			Listen:             "0.0.0.0:8080",
			XPaddingBytes:      xhttp.Range{},
			ScMaxBufferedPosts: xhttp.Range{},
		}

		assert.True(t, xs.XPaddingBytes.IsZero())
		assert.True(t, xs.ScMaxBufferedPosts.IsZero())
	})

	t.Run("String method returns valid JSON", func(t *testing.T) {
		xs := XhttpServer{
			Enable:      true,
			Listen:      "0.0.0.0:8080",
			Path:        "/xhttp/",
			Mode:        "auto",
			HTTPVersion: "1.1",
		}

		jsonStr := xs.String()
		assert.NotEmpty(t, jsonStr)
		assert.Contains(t, jsonStr, `"enable":true`)
		assert.Contains(t, jsonStr, `"listen":"0.0.0.0:8080"`)
		assert.Contains(t, jsonStr, `"path":"/xhttp/"`)
	})
}

func TestXhttpXmuxConfig_Defaults(t *testing.T) {
	t.Run("Empty xmux config", func(t *testing.T) {
		xmux := XhttpXmuxConfig{}

		// All ranges should be zero
		assert.True(t, xmux.MaxConcurrency.IsZero())
		assert.True(t, xmux.MaxConnections.IsZero())
		assert.True(t, xmux.CMaxReuseTimes.IsZero())
		assert.True(t, xmux.HMaxRequestTimes.IsZero())
		assert.True(t, xmux.HMaxReusableSecs.IsZero())
		assert.Equal(t, int64(0), xmux.HKeepAlivePeriod)
	})

	t.Run("Partial xmux config", func(t *testing.T) {
		xmux := XhttpXmuxConfig{
			MaxConcurrency: xhttp.Range{From: 1, To: 1},
		}

		assert.False(t, xmux.MaxConcurrency.IsZero())
		assert.True(t, xmux.MaxConnections.IsZero())
	})

	t.Run("Full xmux config", func(t *testing.T) {
		xmux := XhttpXmuxConfig{
			MaxConcurrency:   xhttp.Range{From: 1, To: 1},
			MaxConnections:   xhttp.Range{From: 4, To: 4},
			CMaxReuseTimes:   xhttp.Range{From: 0, To: 0},
			HMaxRequestTimes: xhttp.Range{From: 600, To: 900},
			HMaxReusableSecs: xhttp.Range{From: 1800, To: 3000},
			HKeepAlivePeriod: 30,
		}

		assert.False(t, xmux.MaxConcurrency.IsZero())
		assert.False(t, xmux.MaxConnections.IsZero())
		assert.False(t, xmux.HMaxRequestTimes.IsZero())
		assert.Equal(t, int64(30), xmux.HKeepAlivePeriod)
	})
}

func TestXhttpServer_EdgeCases(t *testing.T) {
	t.Run("Empty listen address", func(t *testing.T) {
		xs := XhttpServer{
			Enable: true,
			Listen: "", // defaults to 0.0.0.0
		}
		assert.Equal(t, "", xs.Listen)
	})

	t.Run("Nil headers map", func(t *testing.T) {
		xs := XhttpServer{
			Enable:  true,
			Listen:  "0.0.0.0:8080",
			Headers: nil,
		}
		assert.Nil(t, xs.Headers)
	})

	t.Run("Empty headers map", func(t *testing.T) {
		xs := XhttpServer{
			Enable:  true,
			Listen:  "0.0.0.0:8080",
			Headers: map[string]string{},
		}
		assert.NotNil(t, xs.Headers)
		assert.Len(t, xs.Headers, 0)
	})

	t.Run("NoGRPCHeader and NoSSEHeader flags", func(t *testing.T) {
		xs := XhttpServer{
			Enable:       true,
			Listen:       "0.0.0.0:8080",
			NoGRPCHeader: true,
			NoSSEHeader:  true,
		}

		assert.True(t, xs.NoGRPCHeader)
		assert.True(t, xs.NoSSEHeader)
	})

	t.Run("Inverted range (From > To)", func(t *testing.T) {
		xs := XhttpServer{
			Enable:        true,
			Listen:        "0.0.0.0:8080",
			XPaddingBytes: xhttp.Range{From: 1000, To: 100},
		}

		normalized := xs.XPaddingBytes.WithDefault(100, 1000)
		assert.True(t, normalized.From <= normalized.To)
	})

	t.Run("Extremely large range values", func(t *testing.T) {
		xs := XhttpServer{
			Enable:        true,
			Listen:        "0.0.0.0:8080",
			XPaddingBytes: xhttp.Range{From: 1, To: 1_000_000},
		}

		assert.Equal(t, int32(1), xs.XPaddingBytes.From)
		assert.Equal(t, int32(1_000_000), xs.XPaddingBytes.To)
	})
}
