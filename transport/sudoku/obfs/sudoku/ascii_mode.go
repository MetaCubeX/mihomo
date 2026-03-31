package sudoku

import (
	"fmt"
	"strings"
)

const (
	asciiModeTokenASCII   = "ascii"
	asciiModeTokenEntropy = "entropy"
)

// ASCIIMode describes the preferred wire layout for each traffic direction.
// Uplink is client->server, Downlink is server->client.
type ASCIIMode struct {
	Uplink   string
	Downlink string
}

// ParseASCIIMode accepts legacy symmetric values ("ascii"/"entropy"/"prefer_*")
// and directional values like "up_ascii_down_entropy".
func ParseASCIIMode(mode string) (ASCIIMode, error) {
	raw := strings.ToLower(strings.TrimSpace(mode))
	switch raw {
	case "", "entropy", "prefer_entropy":
		return ASCIIMode{Uplink: asciiModeTokenEntropy, Downlink: asciiModeTokenEntropy}, nil
	case "ascii", "prefer_ascii":
		return ASCIIMode{Uplink: asciiModeTokenASCII, Downlink: asciiModeTokenASCII}, nil
	}

	if !strings.HasPrefix(raw, "up_") {
		return ASCIIMode{}, fmt.Errorf("invalid ascii mode: %s", mode)
	}
	parts := strings.SplitN(strings.TrimPrefix(raw, "up_"), "_down_", 2)
	if len(parts) != 2 {
		return ASCIIMode{}, fmt.Errorf("invalid ascii mode: %s", mode)
	}

	up, ok := normalizeASCIIModeToken(parts[0])
	if !ok {
		return ASCIIMode{}, fmt.Errorf("invalid ascii mode: %s", mode)
	}
	down, ok := normalizeASCIIModeToken(parts[1])
	if !ok {
		return ASCIIMode{}, fmt.Errorf("invalid ascii mode: %s", mode)
	}
	return ASCIIMode{Uplink: up, Downlink: down}, nil
}

// NormalizeASCIIMode returns the canonical config string for a supported mode.
func NormalizeASCIIMode(mode string) (string, error) {
	parsed, err := ParseASCIIMode(mode)
	if err != nil {
		return "", err
	}
	return parsed.Canonical(), nil
}

func (m ASCIIMode) Canonical() string {
	if m.Uplink == asciiModeTokenASCII && m.Downlink == asciiModeTokenASCII {
		return "prefer_ascii"
	}
	if m.Uplink == asciiModeTokenEntropy && m.Downlink == asciiModeTokenEntropy {
		return "prefer_entropy"
	}
	return "up_" + m.Uplink + "_down_" + m.Downlink
}

func (m ASCIIMode) uplinkPreference() string {
	return singleDirectionPreference(m.Uplink)
}

func (m ASCIIMode) downlinkPreference() string {
	return singleDirectionPreference(m.Downlink)
}

func normalizeASCIIModeToken(token string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(token)) {
	case "ascii", "prefer_ascii":
		return asciiModeTokenASCII, true
	case "entropy", "prefer_entropy", "":
		return asciiModeTokenEntropy, true
	default:
		return "", false
	}
}

func singleDirectionPreference(token string) string {
	if token == asciiModeTokenASCII {
		return "prefer_ascii"
	}
	return "prefer_entropy"
}
