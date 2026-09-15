package config

import (
	"testing"

	snifferTypes "github.com/metacubex/mihomo/constant/sniffer"

	"github.com/stretchr/testify/assert"
)

func TestParseBitTorrentSniffer(t *testing.T) {
	// sniffer names are matched case-insensitively against the type list
	for _, name := range []string{"BitTorrent", "bittorrent", "BITTORRENT"} {
		cfg, err := parseSniffer(RawSniffer{
			Enable: true,
			Sniff: map[string]RawSniffingConfig{
				name: {},
			},
		}, nil)
		assert.NoError(t, err, name)
		assert.Contains(t, cfg.Sniffers, snifferTypes.BitTorrent, name)
	}
}

func TestParseBitTorrentSnifferLegacyList(t *testing.T) {
	cfg, err := parseSniffer(RawSniffer{
		Enable:   true,
		Sniffing: []string{"BitTorrent"},
	}, nil)
	assert.NoError(t, err)
	assert.Contains(t, cfg.Sniffers, snifferTypes.BitTorrent)
}
