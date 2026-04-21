package networkpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"hash/fnv"
	"net/netip"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/exp/slices"
)

// Sentinel errors returned (wrapped) by NormalizeAndValidate. REST
// handlers use errors.Is to route each failure to its §5.4.8 error
// code without string-matching the human-readable message. Adding a
// new code in the future is a one-line change here plus one
// fmt.Errorf("%w: ...") call at the emission site.
var (
	ErrMalformedBody       = errors.New("malformed_body")
	ErrInvalidVersion      = errors.New("invalid_version")
	ErrInvalidTTL          = errors.New("invalid_ttl")
	ErrTooManyInterfaces   = errors.New("too_many_interfaces")
	ErrDuplicateIfaceName  = errors.New("duplicate_iface_name")
	ErrInvalidGatewayCombo = errors.New("invalid_gateway_combo")
	ErrInvalidField        = errors.New("invalid_field")
)

// MaxInterfaces is the hard cap on interfaces[] length. PUT bodies with
// more entries are rejected with HTTP 400 / too_many_interfaces.
const MaxInterfaces = 32

// NetworkContext is the snapshot host pushes via PUT /network/context.
//
// Shape: multi-interface inventory (Interfaces) + top-level global fields
// (DNSSuffix, TTL). JSON tags use snake_case; Go fields use CamelCase.
// `version` is required and must equal 1; `interfaces` is required and may
// be an empty array ("sampler reported no relevant iface" — rare). Missing
// required fields are rejected at UnmarshalJSON time as malformed_body.
type NetworkContext struct {
	Version    int                `json:"version"`
	Interfaces []InterfaceContext `json:"interfaces"`
	DNSSuffix  []string           `json:"dns_suffix,omitempty"`
	TTL        *int               `json:"ttl,omitempty"`

	// normalizeErr carries a field-path-prefixed parse/normalize error so
	// validate() can surface it as the HTTP 400 cause without depending on
	// per-field typed error variables (keeping the struct shape minimal).
	normalizeErr error
}

// InterfaceContext represents a single active network interface.
//
// Field semantics:
//   - Name: host's iface name (unique within a NetworkContext)
//   - IfaceType: one of ifaceTypes or empty (unknown)
//   - SSID/BSSID: populated for Wi-Fi interfaces; BSSID normalized to
//     lower-case colon form
//   - GatewayIP: the default-route next-hop the host attributes to this
//     iface (filled iff the iface is judged to be a user-visible default
//     route candidate by the sampler policy); GatewayMAC is only filled
//     when GatewayIP is (validate enforces this)
//   - Subnets: on-link CIDRs of the iface (interface address ± netmask);
//     routes carried via the iface (e.g. WireGuard AllowedIPs) are NOT
//     included by sampler contract
//   - Metered: tri-state tag (nil = unknown, true/false = explicit)
type InterfaceContext struct {
	Name       string   `json:"name"`
	IfaceType  string   `json:"iface_type,omitempty"`
	SSID       string   `json:"ssid,omitempty"`
	BSSID      string   `json:"bssid,omitempty"`
	GatewayIP  string   `json:"gateway_ip,omitempty"`
	GatewayMAC string   `json:"gateway_mac,omitempty"`
	Subnets    []string `json:"subnets,omitempty"`
	Metered    *bool    `json:"metered,omitempty"`

	// Derived fields cached by normalize() for matcher hot path.
	gatewayIPParsed netip.Addr
	subnetsParsed   []netip.Prefix
}

// ifaceTypes enumerates the valid iface_type values, in alphabetical order
// so error messages display the set in a stable, easy-to-scan form. The wire
// deliberately does not carry a distinct "tun" value — the host filters
// mihomo's own TUN from interfaces[] by name, so the matcher only sees
// user-installed VPNs as iface_type=vpn.
var ifaceTypes = []string{"cellular", "ethernet", "loopback", "other", "vpn", "wifi", "wwan"}

// IsValidIfaceType reports whether s is a valid iface_type enum value.
// Empty string returns true — a host that can't classify may omit the field.
func IsValidIfaceType(s string) bool {
	if s == "" {
		return true
	}
	return slices.Contains(ifaceTypes, s)
}

// UnmarshalJSON enforces presence of the two required top-level wire fields,
// `version` and `interfaces`. REST handlers translate the returned error to
// HTTP 400 `malformed_body`. Other JSON decoding errors (non-object body,
// type mismatches, malformed UTF-8) also surface here and map to the same
// error code at the handler layer.
func (c *NetworkContext) UnmarshalJSON(data []byte) error {
	var raw struct {
		Version    *int                `json:"version"`
		Interfaces *[]InterfaceContext `json:"interfaces"`
		DNSSuffix  []string            `json:"dns_suffix,omitempty"`
		TTL        *int                `json:"ttl,omitempty"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.Version == nil {
		return fmt.Errorf("%w: missing required field: version", ErrMalformedBody)
	}
	if raw.Interfaces == nil {
		return fmt.Errorf("%w: missing required field: interfaces", ErrMalformedBody)
	}
	c.Version = *raw.Version
	c.Interfaces = *raw.Interfaces
	c.DNSSuffix = raw.DNSSuffix
	c.TTL = raw.TTL
	return nil
}

// NormalizeAndValidate is the single public entry point for preparing a
// NetworkContext. REST handlers call this after json.Unmarshal. Returns nil
// when the context is ready for the Manager; returns an error suitable for
// HTTP 400 passthrough otherwise (mapped to invalid_version / invalid_ttl /
// too_many_interfaces / invalid_field / invalid_gateway_combo /
// duplicate_iface_name by the REST handler).
//
// MaxInterfaces is checked first to short-circuit DoS-ish inputs before
// the per-iface MAC / CIDR parsers run. normalize() then canonicalizes the
// bounded interfaces set so validate() can operate on canonical forms
// (parsed/lowercased/sorted); validate() also reports any error captured
// during normalize() via the normalizeErr carrier.
func (c *NetworkContext) NormalizeAndValidate() error {
	if len(c.Interfaces) > MaxInterfaces {
		return fmt.Errorf("%w: %d entries (max %d)", ErrTooManyInterfaces, len(c.Interfaces), MaxInterfaces)
	}
	c.normalize()
	return c.validate()
}

// normalize rewrites per-iface fields in place + canonicalizes
// DNSSuffix. Idempotent. On first parse error it records the error in
// c.normalizeErr (with the original pre-sort iface index) and stops
// processing further interfaces; validate() reports it as 400.
//
// Note: per-iface validate() and the canonical sort BOTH happen in
// validate(), not here. Per-iface validate runs BEFORE sort so any
// "invalid_field" / "invalid_gateway_combo" errors carry the input-order
// iface index — host can locate the bad iface by the index it sent.
// Sort happens after per-iface validate so duplicate-name detection +
// matcher iteration see canonical order.
//
// Does not mutate `Version` — the wire requires version=1 explicitly;
// deviations are surfaced by validate() as invalid_version.
func (c *NetworkContext) normalize() {
	c.normalizeErr = nil

	for i := range c.Interfaces {
		if err := c.Interfaces[i].normalize(); err != nil {
			// Pre-sort original index so the host can map the error
			// back to the iface they sent.
			c.normalizeErr = withIfacePrefix(err, i)
			// Leave already-normalized prefix entries as-is so Fingerprint()
			// behavior on validated ctx is deterministic even if validate()
			// later rejects; the error propagates through validate().
			break
		}
	}

	c.DNSSuffix = normalizeDNSSuffix(c.DNSSuffix)
}

// validate checks field legality. Must be called after normalize().
// Returns the first error encountered — REST handlers only need one.
//
// The per-iface validate loop and the canonical sort BOTH happen
// here, in this exact order: per-iface validate first (using pre-sort
// indices), then sort, then duplicate-name detection. This way every
// invalid_field / invalid_gateway_combo error path carries the
// input-order iface index, matching what host sent regardless of how
// many ifaces or what their names happened to be.
func (c *NetworkContext) validate() error {
	if c.Version != 1 {
		return fmt.Errorf("%w: got %d (expected 1)", ErrInvalidVersion, c.Version)
	}
	if c.TTL != nil {
		switch {
		case *c.TTL <= 0:
			return fmt.Errorf("%w: %d (must be > 0 or omitted)", ErrInvalidTTL, *c.TTL)
		case *c.TTL > MaxTTLSeconds:
			return fmt.Errorf("%w: %d (max %d seconds = 10 years)", ErrInvalidTTL, *c.TTL, MaxTTLSeconds)
		}
	}
	if len(c.Interfaces) > MaxInterfaces {
		return fmt.Errorf("%w: %d entries (max %d)", ErrTooManyInterfaces, len(c.Interfaces), MaxInterfaces)
	}
	if c.normalizeErr != nil {
		return c.normalizeErr
	}

	// Per-iface field legality, BEFORE canonical sort, so error indices
	// reflect the host's input order (consistent with normalize()'s
	// error indexing).
	for i := range c.Interfaces {
		if err := c.Interfaces[i].validate(); err != nil {
			return withIfacePrefix(err, i)
		}
	}

	// Canonical sort by Name — gives deterministic iteration order in
	// the matcher and lets duplicate-name detection use a single pass.
	slices.SortFunc(c.Interfaces, func(a, b InterfaceContext) int {
		return strings.Compare(a.Name, b.Name)
	})

	// Duplicate-name detection (post-sort). The error reports the name
	// rather than an index because the index would be the post-sort
	// position, which doesn't match the host's input order.
	seen := make(map[string]struct{}, len(c.Interfaces))
	for i := range c.Interfaces {
		if _, ok := seen[c.Interfaces[i].Name]; ok {
			return fmt.Errorf("%w: name=%q", ErrDuplicateIfaceName, c.Interfaces[i].Name)
		}
		seen[c.Interfaces[i].Name] = struct{}{}
	}

	for i, s := range c.DNSSuffix {
		if strings.IndexFunc(s, isForbiddenDNSChar) >= 0 {
			return fmt.Errorf("%w: field: dns_suffix[%d], reason: contains comma, whitespace, or control char", ErrInvalidField, i)
		}
	}
	return nil
}

// invalidField builds an ErrInvalidField error with the canonical
// "field: <path>, reason: <why>" message format required by §5.4.8.
// Callers at the top of the tree supply the full path; iface-level
// callers supply a relative path (like "ssid") and let the outer
// context.validate / context.normalize prefix the "interfaces[N]."
// piece.
func invalidField(path, reason string) error {
	return fmt.Errorf("%w: field: %s, reason: %s", ErrInvalidField, path, reason)
}

// invalidGatewayCombo builds an ErrInvalidGatewayCombo error in the
// same "field: <path>, reason: <why>" shape as invalidField, so host
// log parsers can handle every code uniformly.
func invalidGatewayCombo(path string) error {
	if path == "" {
		// Defensive: iface.validate calls with "" and the outer
		// withIfacePrefix fills the path. If a future caller forgets
		// to wrap, surface a recognizable placeholder rather than
		// emitting "field: , reason: ...".
		path = "<unknown>"
	}
	return fmt.Errorf("%w: field: %s, reason: gateway_mac filled but gateway_ip empty", ErrInvalidGatewayCombo, path)
}

// withIfacePrefix rewrites an iface-level error's field path to include
// the "interfaces[N]." prefix. Preserves the sentinel via the wrapped
// %w so errors.Is continues to work. Returns the original error
// unchanged if it isn't one of our field-path errors.
func withIfacePrefix(err error, idx int) error {
	// gateway_combo is iface-wide; the inner caller's path is always
	// "<unknown>" (or the rare degenerate empty-path), so we just stamp
	// "interfaces[N]" without parsing the message.
	if errors.Is(err, ErrInvalidGatewayCombo) {
		return invalidGatewayCombo(fmt.Sprintf("interfaces[%d]", idx))
	}
	if !errors.Is(err, ErrInvalidField) {
		return err
	}
	// Field-level error: extract "field: <path>, reason: <why>" and
	// rebuild with the iface prefix. Search for ": field: " (with
	// leading colon) to avoid matching the "invalid_field:" sentinel
	// prefix the %w wrap inserts — that would otherwise double-prefix
	// the path. Note: this string-based parse depends on the format
	// invalidField emits — keep both in sync.
	msg := err.Error()
	const marker = ": field: "
	i := strings.Index(msg, marker)
	if i < 0 {
		return err
	}
	rest := msg[i+len(marker):]
	j := strings.Index(rest, ", reason: ")
	if j < 0 {
		return err
	}
	relPath := rest[:j]
	reason := rest[j+len(", reason: "):]
	return invalidField(fmt.Sprintf("interfaces[%d].%s", idx, relPath), reason)
}

// normalize rewrites an InterfaceContext in place. Returns an error on first
// parse failure (prefixed with the field name; caller adds the interfaces[i]
// prefix).
func (iface *InterfaceContext) normalize() error {
	iface.gatewayIPParsed = netip.Addr{}
	iface.subnetsParsed = nil

	if iface.IfaceType != "" {
		iface.IfaceType = strings.ToLower(iface.IfaceType)
	}
	if iface.BSSID != "" {
		m, err := normalizeMAC(iface.BSSID)
		if err != nil {
			return invalidField("bssid", fmt.Sprintf("%q: %s", iface.BSSID, err.Error()))
		}
		iface.BSSID = m
	}
	if iface.GatewayMAC != "" {
		m, err := normalizeMAC(iface.GatewayMAC)
		if err != nil {
			return invalidField("gateway_mac", fmt.Sprintf("%q: %s", iface.GatewayMAC, err.Error()))
		}
		iface.GatewayMAC = m
	}
	if iface.GatewayIP != "" {
		addr, err := netip.ParseAddr(iface.GatewayIP)
		if err != nil {
			return invalidField("gateway_ip", fmt.Sprintf("%q: %s", iface.GatewayIP, err.Error()))
		}
		// Strip IPv6 zone so netip.Prefix.Contains works in matcher (zoned
		// addrs never equal their unzoned siblings).
		addr = addr.WithZone("")
		iface.GatewayIP = addr.String()
		iface.gatewayIPParsed = addr
	}
	if len(iface.Subnets) > 0 {
		parsed := make([]netip.Prefix, 0, len(iface.Subnets))
		for i, raw := range iface.Subnets {
			if raw == "" {
				// Drop empty strings before CIDR parsing.
				continue
			}
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				return invalidField(fmt.Sprintf("subnets[%d]", i), fmt.Sprintf("%q: %s", raw, err.Error()))
			}
			parsed = append(parsed, p.Masked())
		}
		if len(parsed) == 0 {
			iface.Subnets = nil
		} else {
			// Canonical form: sort by String() then dedupe. Derive the string
			// slice from parsed so the two representations cannot drift.
			slices.SortFunc(parsed, func(a, b netip.Prefix) int {
				return strings.Compare(a.String(), b.String())
			})
			parsed = slices.CompactFunc(parsed, func(a, b netip.Prefix) bool {
				return a.String() == b.String()
			})
			normed := make([]string, len(parsed))
			for i, p := range parsed {
				normed[i] = p.String()
			}
			iface.Subnets = normed
			iface.subnetsParsed = parsed
		}
	}
	return nil
}

// validate checks legality of the already-normalized interface. All
// field-level failures emit ErrInvalidField with the relative path
// ("name" / "ssid" / ...); the caller prefixes "interfaces[N]." before
// surfacing to the REST layer.
func (iface *InterfaceContext) validate() error {
	if iface.Name == "" {
		return invalidField("name", "empty (required)")
	}
	if len(iface.Name) > 255 {
		return invalidField("name", fmt.Sprintf("%d bytes (max 255)", len(iface.Name)))
	}
	if len(iface.SSID) > 32 {
		return invalidField("ssid", fmt.Sprintf("%d bytes (max 32)", len(iface.SSID)))
	}
	if iface.IfaceType != "" && !IsValidIfaceType(iface.IfaceType) {
		return invalidField("iface_type", fmt.Sprintf("%q not in %s", iface.IfaceType, strings.Join(ifaceTypes, "/")))
	}
	// gateway_mac is only meaningful when gateway_ip is also filled; they
	// must be filled together or both empty. Uses a distinct sentinel so
	// the REST layer can emit its own error code.
	if iface.GatewayMAC != "" && iface.GatewayIP == "" {
		// Path is supplied by the outer context.validate via withIfacePrefix.
		return invalidGatewayCombo("")
	}
	return nil
}

// isForbiddenDNSChar rejects whitespace, control characters, and commas.
// Comma is forbidden because Fingerprint() joins dns_suffix entries with
// ","; allowing commas in values would create within-field aliasing
// (["a,b"] and ["a","b"] would hash to the same fingerprint).
func isForbiddenDNSChar(r rune) bool {
	return r == ',' || unicode.IsSpace(r) || unicode.IsControl(r)
}

// Fingerprint returns a stable hash of the semantic content of c (TTL excluded).
// Format: 16-char lower-case hex of an fnv64a digest over length-prefixed
// fields in a deterministic order.
//
// Canonical encoding:
//   - missing / null / empty per-iface scalars → ""
//   - empty subnets / empty dns_suffix → ""
//   - metered tri-state → "null" / "true" / "false"
//   - version → "1" (literal string)
//
// Interfaces are iterated in sort-by-name order (normalize() already sorted).
// Key prefix "iface.{idx}." binds each field to its row so that any
// cross-language reimplementation of the hasher can reproduce the byte
// stream exactly given the same canonical context.
func (c *NetworkContext) Fingerprint() string {
	h := fnv.New64a()
	for idx := range c.Interfaces {
		iface := &c.Interfaces[idx]
		writeFingerprintField(h, fmt.Sprintf("iface.%d.name", idx), iface.Name)
		writeFingerprintField(h, fmt.Sprintf("iface.%d.iface_type", idx), iface.IfaceType)
		writeFingerprintField(h, fmt.Sprintf("iface.%d.ssid", idx), iface.SSID)
		writeFingerprintField(h, fmt.Sprintf("iface.%d.bssid", idx), iface.BSSID)
		writeFingerprintField(h, fmt.Sprintf("iface.%d.gateway_ip", idx), iface.GatewayIP)
		writeFingerprintField(h, fmt.Sprintf("iface.%d.gateway_mac", idx), iface.GatewayMAC)
		writeFingerprintField(h, fmt.Sprintf("iface.%d.subnets", idx), strings.Join(iface.Subnets, ","))
		writeFingerprintField(h, fmt.Sprintf("iface.%d.metered", idx), meteredString(iface.Metered))
	}
	writeFingerprintField(h, "dns_suffix", strings.Join(c.DNSSuffix, ","))
	// The version field is encoded as the literal string "1" (not
	// strconv.Itoa(c.Version)) so Fingerprint stays byte-stable even if
	// called before a successful NormalizeAndValidate — which would
	// otherwise leave Version at whatever the wire payload said. This is
	// also the rule any cross-impl implementation (e.g. the host-side
	// Rust fingerprint) must follow to keep byte parity.
	writeFingerprintField(h, "version", "1")
	return fmt.Sprintf("%016x", h.Sum64())
}

// writeFingerprintField emits "<name>=<len>:<value>\n". Length prefix defeats
// cross-field aliasing (e.g. a value containing "name=...\n" can't collide
// with a context that has those markers as real field values).
func writeFingerprintField(h hash.Hash64, name, value string) {
	h.Write([]byte(name))
	h.Write([]byte{'='})
	h.Write([]byte(strconv.Itoa(len(value))))
	h.Write([]byte{':'})
	h.Write([]byte(value))
	h.Write([]byte{'\n'})
}
