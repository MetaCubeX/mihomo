package outbound

import (
	"context"
	"testing"

	tlsC "github.com/metacubex/mihomo/component/tls"
	"github.com/metacubex/mihomo/transport/xhttp"

	"github.com/stretchr/testify/assert"
)

func TestXHTTPTLSOptionsCloneForDownload(t *testing.T) {
	trueValue := true
	falseValue := false
	reality := &tlsC.RealityConfig{}

	base := xhttpTLSOptions{
		Address:    "upload.example.com:443",
		TLSEnabled: true,
		ServerName: "upload.example.com",
		Reality:    reality,
	}

	t.Run("Inherit", func(t *testing.T) {
		clone, err := base.cloneForDownload(&xhttp.DownloadConfig{
			Server: "download.example.com",
			Port:   8443,
		})
		assert.NoError(t, err)
		assert.Equal(t, "download.example.com:8443", clone.Address)
		assert.True(t, clone.TLSEnabled)
		assert.Same(t, reality, clone.Reality)
	})

	t.Run("ExplicitTLSClearsReality", func(t *testing.T) {
		clone, err := base.cloneForDownload(&xhttp.DownloadConfig{
			TLS: &trueValue,
		})
		assert.NoError(t, err)
		assert.True(t, clone.TLSEnabled)
		assert.Nil(t, clone.Reality)
	})

	t.Run("ExplicitPlainDisablesTLS", func(t *testing.T) {
		clone, err := base.cloneForDownload(&xhttp.DownloadConfig{
			TLS: &falseValue,
		})
		assert.NoError(t, err)
		assert.False(t, clone.TLSEnabled)
		assert.Nil(t, clone.Reality)
	})

	t.Run("RealityImpliesTLS", func(t *testing.T) {
		clone, err := (xhttpTLSOptions{Address: "download.example.com:80"}).cloneForDownload(&xhttp.DownloadConfig{
			Reality: reality,
		})
		assert.NoError(t, err)
		assert.True(t, clone.TLSEnabled)
		assert.Same(t, reality, clone.Reality)
	})

	t.Run("RealityRequiresTLS", func(t *testing.T) {
		_, err := base.cloneForDownload(&xhttp.DownloadConfig{
			TLS:     &falseValue,
			Reality: reality,
		})
		assert.ErrorContains(t, err, "reality-opts requires tls")
	})

	t.Run("OverrideServerNameAndFingerprint", func(t *testing.T) {
		clone, err := base.cloneForDownload(&xhttp.DownloadConfig{
			ServerName:        "download.example.com",
			ClientFingerprint: "firefox",
		})
		assert.NoError(t, err)
		assert.Equal(t, "download.example.com", clone.ServerName)
		assert.Equal(t, "firefox", clone.ClientFingerprint)
	})
}

func TestBuildXHTTPConfigUsesNetworkSpecificOptions(t *testing.T) {
	cfg, err := buildXHTTPConfig("xhttp", "example.com:443", "", nil,
		XHTTPOptions{
			Path: "/xhttp",
			Host: "xhttp.example.com",
		},
		SplitHTTPOptions{
			Path: "/splithttp",
			Host: "split.example.com",
		},
		false,
	)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, "/xhttp", cfg.Path)
	assert.Equal(t, "xhttp.example.com", cfg.Host)

	cfg, err = buildXHTTPConfig("splithttp", "example.com:443", "", nil,
		XHTTPOptions{
			Path: "/xhttp",
			Host: "xhttp.example.com",
		},
		SplitHTTPOptions{
			Path: "/splithttp",
			Host: "split.example.com",
		},
		false,
	)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, "/splithttp", cfg.Path)
	assert.Equal(t, "split.example.com", cfg.Host)
}

func TestDialXHTTPConnRejectsStreamOneWithDownloadSettings(t *testing.T) {
	cfg := &xhttp.Config{
		Mode: "stream-one",
		DownloadSettings: &xhttp.DownloadConfig{
			Host: "download.example.com",
		},
	}

	_, err := dialXHTTPConn(context.Background(), nil, cfg, xhttpTLSOptions{
		Address: "upload.example.com:443",
	})
	assert.ErrorContains(t, err, `mode "stream-one" cannot be used with download-settings`)
}
