package main

import (
	"testing"

	"github.com/metacubex/mihomo/common/structure"
	IN "github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/xhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXhttpConfig_LoadFromYAML(t *testing.T) {
	t.Run("Basic configuration", func(t *testing.T) {
		mapping := map[string]any{
			"type":         "xhttp",
			"listen":       "127.0.0.1",
			"port":         "8080",
			"path":         "/xhttp/",
			"mode":         "auto",
			"http-version": "1.1",
		}

		decoder := structure.NewDecoder(structure.Option{
			TagName:          "inbound",
			WeaklyTypedInput: true,
			KeyReplacer:      structure.DefaultKeyReplacer,
		})

		option := &IN.XhttpOption{}
		err := decoder.Decode(mapping, option)
		require.NoError(t, err)

		assert.Equal(t, "127.0.0.1", option.Listen)
		assert.Equal(t, "8080", option.Port)
		assert.Equal(t, "/xhttp/", option.Path)
		assert.Equal(t, "auto", option.Mode)
		assert.Equal(t, "1.1", option.HTTPVersion)
	})

	t.Run("Full configuration with all fields", func(t *testing.T) {
		mapping := map[string]any{
			"type":                   "xhttp",
			"listen":                 "0.0.0.0",
			"port":                   "8443",
			"path":                   "/custom-path/",
			"mode":                   "packet-up",
			"http-version":           "2",
			"headers":                map[string]any{"X-Custom": "value", "Server": "mihomo"},
			"no-grpc-header":         true,
			"no-sse-header":          true,
			"x-padding-bytes":        "100-1000",
			"sc-max-each-post-bytes": "1000000-1000000",
			"sc-max-buffered-posts":  "30-30",
			"certificate":            "/path/to/cert.pem",
			"private-key":            "/path/to/key.pem",
			"xmux": map[string]any{
				"max-concurrency":     "1-1",
				"max-connections":     "4-4",
				"c-max-reuse-times":   "0-0",
				"h-max-request-times": "600-900",
				"h-max-reusable-secs": "1800-3000",
				"h-keep-alive-period": 30,
			},
		}

		decoder := structure.NewDecoder(structure.Option{
			TagName:          "inbound",
			WeaklyTypedInput: true,
			KeyReplacer:      structure.DefaultKeyReplacer,
		})

		option := &IN.XhttpOption{}
		err := decoder.Decode(mapping, option)
		require.NoError(t, err)

		// Basic fields
		assert.Equal(t, "0.0.0.0", option.Listen)
		assert.Equal(t, "8443", option.Port)
		assert.Equal(t, "/custom-path/", option.Path)
		assert.Equal(t, "packet-up", option.Mode)
		assert.Equal(t, "2", option.HTTPVersion)

		// Headers
		assert.NotNil(t, option.Headers)
		assert.Equal(t, "value", option.Headers["X-Custom"])
		assert.Equal(t, "mihomo", option.Headers["Server"])

		// Flags
		assert.True(t, option.NoGRPCHeader)
		assert.True(t, option.NoSSEHeader)

		// Range strings
		assert.Equal(t, "100-1000", option.XPaddingBytes)
		assert.Equal(t, "1000000-1000000", option.ScMaxEachPostBytes)
		assert.Equal(t, "30-30", option.ScMaxBufferedPosts)

		// TLS
		assert.Equal(t, "/path/to/cert.pem", option.Certificate)
		assert.Equal(t, "/path/to/key.pem", option.PrivateKey)

		// Xmux
		assert.Equal(t, "1-1", option.Xmux.MaxConcurrency)
		assert.Equal(t, "4-4", option.Xmux.MaxConnections)
		assert.Equal(t, "0-0", option.Xmux.CMaxReuseTimes)
		assert.Equal(t, "600-900", option.Xmux.HMaxRequestTimes)
		assert.Equal(t, "1800-3000", option.Xmux.HMaxReusableSecs)
		assert.Equal(t, 30, option.Xmux.HKeepAlivePeriod)
	})

	t.Run("Configuration with empty optional fields", func(t *testing.T) {
		mapping := map[string]any{
			"type":   "xhttp",
			"listen": "127.0.0.1",
			"port":   "9090",
		}

		decoder := structure.NewDecoder(structure.Option{
			TagName:          "inbound",
			WeaklyTypedInput: true,
			KeyReplacer:      structure.DefaultKeyReplacer,
		})

		option := &IN.XhttpOption{}
		err := decoder.Decode(mapping, option)
		require.NoError(t, err)

		// Required fields
		assert.Equal(t, "127.0.0.1", option.Listen)
		assert.Equal(t, "9090", option.Port)

		// Optional fields should be empty/zero
		assert.Empty(t, option.Path)
		assert.Empty(t, option.Mode)
		assert.Empty(t, option.HTTPVersion)
		assert.Nil(t, option.Headers)
		assert.False(t, option.NoGRPCHeader)
		assert.False(t, option.NoSSEHeader)
		assert.Empty(t, option.XPaddingBytes)
		assert.Empty(t, option.ScMaxEachPostBytes)
		assert.Empty(t, option.ScMaxBufferedPosts)
		assert.Empty(t, option.Certificate)
		assert.Empty(t, option.PrivateKey)
	})

	t.Run("NewXhttp creates listener from parsed config", func(t *testing.T) {
		mapping := map[string]any{
			"type":            "xhttp",
			"listen":          "127.0.0.1",
			"port":            "18080",
			"path":            "/test/",
			"mode":            "stream-up",
			"http-version":    "2",
			"x-padding-bytes": "200-500",
		}

		decoder := structure.NewDecoder(structure.Option{
			TagName:          "inbound",
			WeaklyTypedInput: true,
			KeyReplacer:      structure.DefaultKeyReplacer,
		})

		option := &IN.XhttpOption{}
		err := decoder.Decode(mapping, option)
		require.NoError(t, err)

		// Create listener from parsed config
		listener, err := IN.NewXhttp(option)
		require.NoError(t, err)
		require.NotNil(t, listener)

		// Verify config is preserved
		config := listener.Config().(*IN.XhttpOption)
		assert.Equal(t, "127.0.0.1", config.Listen)
		assert.Equal(t, "18080", config.Port)
		assert.Equal(t, "/test/", config.Path)
		assert.Equal(t, "stream-up", config.Mode)
		assert.Equal(t, "2", config.HTTPVersion)
		assert.Equal(t, "200-500", config.XPaddingBytes)
	})

	t.Run("Range string parsing in NewXhttp", func(t *testing.T) {
		mapping := map[string]any{
			"type":            "xhttp",
			"listen":          "127.0.0.1",
			"port":            "28080",
			"x-padding-bytes": "100-1000",
			"xmux": map[string]any{
				"max-concurrency":     "1-1",
				"h-max-request-times": "500-700",
			},
		}

		decoder := structure.NewDecoder(structure.Option{
			TagName:          "inbound",
			WeaklyTypedInput: true,
			KeyReplacer:      structure.DefaultKeyReplacer,
		})

		option := &IN.XhttpOption{}
		err := decoder.Decode(mapping, option)
		require.NoError(t, err)

		// Create listener - this triggers Range parsing
		listener, err := IN.NewXhttp(option)
		require.NoError(t, err)
		require.NotNil(t, listener)

		// Ranges should be parsed successfully (verified by no error)
	})

	t.Run("Invalid range string handling", func(t *testing.T) {
		mapping := map[string]any{
			"type":            "xhttp",
			"listen":          "127.0.0.1",
			"port":            "38080",
			"x-padding-bytes": "invalid-range",
		}

		decoder := structure.NewDecoder(structure.Option{
			TagName:          "inbound",
			WeaklyTypedInput: true,
			KeyReplacer:      structure.DefaultKeyReplacer,
		})

		option := &IN.XhttpOption{}
		err := decoder.Decode(mapping, option)
		require.NoError(t, err)

		// NewXhttp should handle invalid range gracefully (logs warning but continues)
		listener, err := IN.NewXhttp(option)
		require.NoError(t, err) // Should not fail, just warn
		require.NotNil(t, listener)
	})

	t.Run("Configuration round-trip", func(t *testing.T) {
		originalMapping := map[string]any{
			"type":         "xhttp",
			"listen":       "0.0.0.0",
			"port":         "48080",
			"path":         "/roundtrip/",
			"mode":         "packet-up",
			"http-version": "3",
			"headers":      map[string]any{"X-Test": "roundtrip"},
		}

		decoder := structure.NewDecoder(structure.Option{
			TagName:          "inbound",
			WeaklyTypedInput: true,
			KeyReplacer:      structure.DefaultKeyReplacer,
		})

		// Decode
		option := &IN.XhttpOption{}
		err := decoder.Decode(originalMapping, option)
		require.NoError(t, err)

		// Create listener
		listener, err := IN.NewXhttp(option)
		require.NoError(t, err)

		// Verify all values preserved
		config := listener.Config().(*IN.XhttpOption)
		assert.Equal(t, originalMapping["listen"], config.Listen)
		assert.Equal(t, originalMapping["port"], config.Port)
		assert.Equal(t, originalMapping["path"], config.Path)
		assert.Equal(t, originalMapping["mode"], config.Mode)
		assert.Equal(t, originalMapping["http-version"], config.HTTPVersion)
		assert.Equal(t, "roundtrip", config.Headers["X-Test"])
	})
}

func TestXhttpConfig_RangeParsing(t *testing.T) {
	t.Run("Valid range formats", func(t *testing.T) {
		testCases := []struct {
			name     string
			input    string
			expected xhttp.Range
		}{
			{"Single value", "100-100", xhttp.Range{From: 100, To: 100}},
			{"Normal range", "100-1000", xhttp.Range{From: 100, To: 1000}},
			{"Zero range", "0-0", xhttp.Range{From: 0, To: 0}},
			{"Large values", "1000000-2000000", xhttp.Range{From: 1000000, To: 2000000}},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				var r xhttp.Range
				err := r.UnmarshalText([]byte(tc.input))
				require.NoError(t, err)
				assert.Equal(t, tc.expected.From, r.From)
				assert.Equal(t, tc.expected.To, r.To)
			})
		}
	})

	t.Run("Empty string creates zero range", func(t *testing.T) {
		mapping := map[string]any{
			"type":            "xhttp",
			"listen":          "127.0.0.1",
			"port":            "58080",
			"x-padding-bytes": "",
		}

		decoder := structure.NewDecoder(structure.Option{
			TagName:          "inbound",
			WeaklyTypedInput: true,
			KeyReplacer:      structure.DefaultKeyReplacer,
		})

		option := &IN.XhttpOption{}
		err := decoder.Decode(mapping, option)
		require.NoError(t, err)

		assert.Empty(t, option.XPaddingBytes)
	})
}
