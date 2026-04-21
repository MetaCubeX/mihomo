package networkpolicy

import (
	"fmt"
	"strings"

	"golang.org/x/exp/slices"
)

// normalizeMAC returns s as a lower-case colon-separated MAC address.
//
// Accepted input formats (case-insensitive; separator must be uniform):
//
//	colon:      "aa:bb:cc:dd:ee:ff"
//	dash:       "aa-bb-cc-dd-ee-ff"
//	unseparated "aabbccddeeff"
//
// Any other form (mixed separators, wrong group count, non-hex characters)
// returns an error.
func normalizeMAC(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("expected MAC, got empty string")
	}
	hasColon := strings.ContainsRune(s, ':')
	hasDash := strings.ContainsRune(s, '-')
	var hex string
	switch {
	case hasColon && hasDash:
		return "", fmt.Errorf("expected MAC, got %q (mixed separators)", s)
	case hasColon:
		parts := strings.Split(s, ":")
		if len(parts) != 6 {
			return "", fmt.Errorf("expected MAC, got %q (need 6 colon-separated groups)", s)
		}
		for i, p := range parts {
			if len(p) != 2 {
				return "", fmt.Errorf("expected MAC, got %q (group %d is not 2 hex chars)", s, i)
			}
		}
		hex = strings.Join(parts, "")
	case hasDash:
		parts := strings.Split(s, "-")
		if len(parts) != 6 {
			return "", fmt.Errorf("expected MAC, got %q (need 6 dash-separated groups)", s)
		}
		for i, p := range parts {
			if len(p) != 2 {
				return "", fmt.Errorf("expected MAC, got %q (group %d is not 2 hex chars)", s, i)
			}
		}
		hex = strings.Join(parts, "")
	default:
		if len(s) != 12 {
			return "", fmt.Errorf("expected MAC, got %q (unseparated form must be 12 hex chars)", s)
		}
		hex = s
	}
	if !isHex(hex) {
		return "", fmt.Errorf("expected MAC, got %q (non-hex character)", s)
	}
	hex = strings.ToLower(hex)
	var b strings.Builder
	b.Grow(17)
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hex[i : i+2])
	}
	return b.String(), nil
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// meteredString renders *bool as a stable string for Fingerprint.
func meteredString(b *bool) string {
	switch {
	case b == nil:
		return "null"
	case *b:
		return "true"
	default:
		return "false"
	}
}

// normalizeDNSSuffix applies the canonical form for the top-level dns_suffix
// field: lower-case each entry, drop empty strings, sort, dedupe. Returns
// nil for empty/all-empty input.
func normalizeDNSSuffix(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		out = append(out, strings.ToLower(s))
	}
	if len(out) == 0 {
		return nil
	}
	slices.Sort(out)
	out = slices.Compact(out)
	return out
}
