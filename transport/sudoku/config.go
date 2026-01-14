package sudoku

import (
	"fmt"
	"strings"

	"github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
)

// ProtocolConfig defines the configuration for the Sudoku protocol stack.
// It is intentionally kept close to the upstream Sudoku project to ensure wire compatibility.
type ProtocolConfig struct {
	// Client-only: "host:port".
	ServerAddress string

	// Pre-shared key (or ED25519 key material) used to derive crypto and tables.
	Key string

	// "aes-128-gcm", "chacha20-poly1305", or "none".
	AEADMethod string

	// Table is the single obfuscation table to use when table rotation is disabled.
	Table *sudoku.Table

	// Tables is an optional candidate set for table rotation.
	// If provided (len>0), the client will pick one table per connection and the server will
	// probe the handshake to detect which one was used, keeping the handshake format unchanged.
	// When Tables is set, Table may be nil.
	Tables []*sudoku.Table

	// Padding insertion ratio (0-100). Must satisfy PaddingMax >= PaddingMin.
	PaddingMin int
	PaddingMax int

	// EnablePureDownlink toggles the bandwidth-optimized downlink mode.
	EnablePureDownlink bool

	// Client-only: final target "host:port".
	TargetAddress string

	// Server-side handshake timeout (seconds).
	HandshakeTimeoutSeconds int

	// DisableHTTPMask disables all HTTP camouflage layers.
	DisableHTTPMask bool

	// HTTPMaskMode controls how the HTTP layer behaves:
	//   - "legacy": write a fake HTTP/1.1 header then switch to raw stream (default, not CDN-compatible)
	//   - "stream": real HTTP tunnel (stream-one or split), CDN-compatible
	//   - "poll": plain HTTP tunnel (authorize/push/pull), strong restricted-network pass-through
	//   - "auto": try stream then fall back to poll
	HTTPMaskMode string

	// HTTPMaskTLSEnabled enables HTTPS for HTTP tunnel modes (client-side).
	// If false, the tunnel uses HTTP (no port-based inference).
	HTTPMaskTLSEnabled bool

	// HTTPMaskHost optionally overrides the HTTP Host header / SNI host for HTTP tunnel modes (client-side).
	HTTPMaskHost string

	// HTTPMaskPathRoot optionally prefixes all HTTP mask paths with a first-level segment.
	// Example: "aabbcc" => "/aabbcc/session", "/aabbcc/api/v1/upload", ...
	HTTPMaskPathRoot string

	// HTTPMaskMultiplex controls multiplex behavior when HTTPMask tunnel modes are enabled:
	//   - "off": disable reuse; each Dial establishes its own HTTPMask tunnel
	//   - "auto": reuse underlying HTTP connections across multiple tunnel dials (HTTP/1.1 keep-alive / HTTP/2)
	//   - "on": enable "single tunnel, multi-target" mux (Sudoku-level multiplex; Dial behaves like "auto" otherwise)
	HTTPMaskMultiplex string
}

func (c *ProtocolConfig) Validate() error {
	if c.Table == nil && len(c.Tables) == 0 {
		return fmt.Errorf("table cannot be nil (or provide tables)")
	}
	for i, t := range c.Tables {
		if t == nil {
			return fmt.Errorf("tables[%d] cannot be nil", i)
		}
	}

	if c.Key == "" {
		return fmt.Errorf("key cannot be empty")
	}

	switch c.AEADMethod {
	case "aes-128-gcm", "chacha20-poly1305", "none":
	default:
		return fmt.Errorf("invalid aead-method: %s, must be one of: aes-128-gcm, chacha20-poly1305, none", c.AEADMethod)
	}

	if c.PaddingMin < 0 || c.PaddingMin > 100 {
		return fmt.Errorf("padding-min must be between 0 and 100, got %d", c.PaddingMin)
	}
	if c.PaddingMax < 0 || c.PaddingMax > 100 {
		return fmt.Errorf("padding-max must be between 0 and 100, got %d", c.PaddingMax)
	}
	if c.PaddingMax < c.PaddingMin {
		return fmt.Errorf("padding-max (%d) must be >= padding-min (%d)", c.PaddingMax, c.PaddingMin)
	}

	if !c.EnablePureDownlink && c.AEADMethod == "none" {
		return fmt.Errorf("bandwidth optimized downlink requires AEAD")
	}

	if c.HandshakeTimeoutSeconds < 0 {
		return fmt.Errorf("handshake-timeout must be >= 0, got %d", c.HandshakeTimeoutSeconds)
	}

	switch strings.ToLower(strings.TrimSpace(c.HTTPMaskMode)) {
	case "", "legacy", "stream", "poll", "auto":
	default:
		return fmt.Errorf("invalid http-mask-mode: %s, must be one of: legacy, stream, poll, auto", c.HTTPMaskMode)
	}

	if v := strings.TrimSpace(c.HTTPMaskPathRoot); v != "" {
		if strings.Contains(v, "/") {
			return fmt.Errorf("invalid http-mask-path-root: must be a single path segment")
		}
		for i := 0; i < len(v); i++ {
			ch := v[i]
			switch {
			case ch >= 'a' && ch <= 'z':
			case ch >= 'A' && ch <= 'Z':
			case ch >= '0' && ch <= '9':
			case ch == '_' || ch == '-':
			default:
				return fmt.Errorf("invalid http-mask-path-root: contains invalid character %q", ch)
			}
		}
	}

	switch strings.ToLower(strings.TrimSpace(c.HTTPMaskMultiplex)) {
	case "", "off", "auto", "on":
	default:
		return fmt.Errorf("invalid http-mask-multiplex: %s, must be one of: off, auto, on", c.HTTPMaskMultiplex)
	}

	return nil
}

func (c *ProtocolConfig) ValidateClient() error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.ServerAddress == "" {
		return fmt.Errorf("server address cannot be empty")
	}
	if c.TargetAddress == "" {
		return fmt.Errorf("target address cannot be empty")
	}
	return nil
}

func DefaultConfig() *ProtocolConfig {
	return &ProtocolConfig{
		AEADMethod:              "chacha20-poly1305",
		PaddingMin:              10,
		PaddingMax:              30,
		EnablePureDownlink:      true,
		HandshakeTimeoutSeconds: 5,
		HTTPMaskMode:            "legacy",
		HTTPMaskMultiplex:       "off",
	}
}

func (c *ProtocolConfig) tableCandidates() []*sudoku.Table {
	if c == nil {
		return nil
	}
	if len(c.Tables) > 0 {
		return c.Tables
	}
	if c.Table != nil {
		return []*sudoku.Table{c.Table}
	}
	return nil
}
