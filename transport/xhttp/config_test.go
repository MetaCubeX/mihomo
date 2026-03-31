package xhttp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigEffectiveMode(t *testing.T) {
	testCases := []struct {
		name   string
		config Config
		want   string
	}{
		{
			name: "DefaultH2AutoUsesStreamUp",
			config: Config{
				ALPN: []string{"h2"},
			},
			want: "stream-up",
		},
		{
			name: "RealityAutoUsesStreamOne",
			config: Config{
				ALPN:       []string{"h2"},
				HasReality: true,
			},
			want: "stream-one",
		},
		{
			name: "DownloadSettingsForceStreamUp",
			config: Config{
				ALPN: []string{"h3"},
				DownloadSettings: &DownloadConfig{
					Host: "download.example.com",
				},
			},
			want: "stream-up",
		},
		{
			name: "H3OnlyAutoUsesPacketUp",
			config: Config{
				ALPN: []string{"h3"},
			},
			want: "packet-up",
		},
		{
			name: "ExplicitModeWins",
			config: Config{
				Mode: "packet-up",
				ALPN: []string{"h2"},
			},
			want: "packet-up",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.want, testCase.config.EffectiveMode())
		})
	}
}

func TestConfigDownloadRequestConfig(t *testing.T) {
	config := &Config{
		Host:       "upload.example.com",
		Path:       "/upload",
		Mode:       "stream-up",
		Headers:    map[string]string{"X-Test": "upload"},
		ALPN:       []string{"h2"},
		TryQUIC:    true,
		HasReality: true,
		DownloadSettings: &DownloadConfig{
			Host:    "download.example.com",
			Path:    "/download",
			Mode:    "packet-up",
			Headers: map[string]string{"X-Test": "download"},
		},
	}

	download := config.DownloadRequestConfig()
	assert.Equal(t, "download.example.com", download.Host)
	assert.Equal(t, "/download", download.Path)
	assert.Equal(t, "packet-up", download.Mode)
	assert.Equal(t, "download", download.Headers["X-Test"])
	assert.Equal(t, config.ALPN, download.ALPN)
	assert.Equal(t, config.TryQUIC, download.TryQUIC)
	assert.Equal(t, config.HasReality, download.HasReality)
	assert.Nil(t, download.DownloadSettings)
}
