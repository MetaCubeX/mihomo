package config

import (
	"bytes"
	"strconv"
	"strings"
)

// ManagedConfig describes a self-update subscription embedded as a leading
// directive in the configuration file, compatible with Surge
// (`#!MANAGED-CONFIG <url> [interval=<seconds>] [strict=<bool>]`) and Stash
// (`#SUBSCRIBED <url>`).
//
// mihomo does not fetch the URL itself; the value is surfaced through the API
// (GET /configs) so the controlling client can keep the configuration updated
// even when the provider changes the subscription domain.
type ManagedConfig struct {
	URL      string `json:"url"`
	Interval int    `json:"interval,omitempty"`
	Strict   bool   `json:"strict,omitempty"`
}

// pointerOrNil returns a pointer to the value, or nil when no directive was
// present (empty URL), so it is omitted from the General config / API output.
func (mc ManagedConfig) pointerOrNil() *ManagedConfig {
	if mc.URL == "" {
		return nil
	}
	return &mc
}

const (
	managedConfigDirective = "#!MANAGED-CONFIG" // Surge
	subscribedDirective    = "#SUBSCRIBED"      // Stash
)

// parseManagedConfig scans the leading comment lines of a raw configuration for
// a managed-config / subscribed directive. The first directive found wins;
// scanning stops at the first non-comment, non-blank line so a stray match in
// the configuration body is never picked up. Returns the zero value when no
// directive is present.
func parseManagedConfig(buf []byte) (mc ManagedConfig) {
	for len(buf) > 0 {
		var raw []byte
		raw, buf, _ = bytes.Cut(buf, []byte{'\n'})

		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "#") {
			break // reached the configuration body
		}
		upper := strings.ToUpper(line)

		// match a directive keyword on a whole-token boundary. The keyword must
		// directly follow '#' (no space), so ordinary comments such as
		// "# SUBSCRIBED to ..." are not mistaken for a directive.
		match := func(keyword string) (args string, ok bool) {
			if !strings.HasPrefix(upper, keyword) {
				return "", false
			}
			if len(line) == len(keyword) {
				return "", true
			}
			switch line[len(keyword)] {
			case ' ', '\t':
				return line[len(keyword):], true
			default:
				return "", false
			}
		}

		var args string
		if a, ok := match(managedConfigDirective); ok {
			args = a
		} else if a, ok := match(subscribedDirective); ok {
			args = a
		} else {
			continue
		}

		fields := strings.Fields(args)
		if len(fields) == 0 {
			continue
		}
		mc.URL = strings.Trim(fields[0], `"'`)
		for _, field := range fields[1:] {
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			switch strings.ToLower(key) {
			case "interval":
				if n, err := strconv.Atoi(value); err == nil {
					mc.Interval = n
				}
			case "strict":
				mc.Strict = strings.EqualFold(value, "true")
			}
		}
		return mc
	}
	return mc
}
