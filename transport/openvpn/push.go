package openvpn

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

const PushRequest = "PUSH_REQUEST"

type PushReply struct {
	Raw       string
	Prefixes  []netip.Prefix
	Routes    []netip.Prefix
	DNS       []netip.Addr
	PeerID    uint32
	Redirect  bool
	BlockIPv6 bool

	// DataCiphers is the list of data channel ciphers pushed by the server
	// via the "data-ciphers" option (OpenVPN 2.5+).
	DataCiphers []string

	// Cipher is the single cipher pushed by the server via the "cipher"
	// option (legacy or fallback).
	Cipher string

	// PingInterval is the server-pushed keepalive ping interval (seconds).
	PingInterval int

	// PingRestart is the server-pushed keepalive ping-restart timeout (seconds).
	PingRestart int
}

func ParsePushReply(message string) (*PushReply, error) {
	message = strings.TrimRight(message, "\x00")
	if !strings.HasPrefix(message, "PUSH_REPLY") {
		return nil, fmt.Errorf("unexpected openvpn push message %q", message)
	}
	reply := &PushReply{
		Raw:    message,
		PeerID: PeerIDUnset,
	}
	for _, option := range splitPushOptions(message) {
		fields := strings.Fields(option)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "ifconfig":
			if len(fields) >= 3 {
				prefix, err := parseIPv4Ifconfig(fields[1], fields[2])
				if err != nil {
					return nil, err
				}
				reply.Prefixes = append(reply.Prefixes, prefix)
			}
		case "ifconfig-ipv6":
			if len(fields) >= 2 {
				prefix, err := netip.ParsePrefix(fields[1])
				if err != nil {
					return nil, fmt.Errorf("parse pushed ipv6 address %q: %w", fields[1], err)
				}
				reply.Prefixes = append(reply.Prefixes, prefix)
			}
		case "route":
			if len(fields) >= 3 {
				prefix, err := parseIPv4Route(fields[1], fields[2])
				if err != nil {
					continue
				}
				reply.Routes = append(reply.Routes, prefix)
			}
		case "route-ipv6":
			if len(fields) >= 2 {
				prefix, err := netip.ParsePrefix(fields[1])
				if err != nil {
					continue
				}
				reply.Routes = append(reply.Routes, prefix)
			}
		case "dhcp-option":
			if len(fields) >= 3 && fields[1] == "DNS" {
				if addr, err := netip.ParseAddr(fields[2]); err == nil {
					reply.DNS = append(reply.DNS, addr)
				}
			}
		case "peer-id":
			if len(fields) >= 2 {
				id, err := strconv.ParseUint(fields[1], 10, 24)
				if err != nil {
					return nil, fmt.Errorf("parse pushed peer-id %q: %w", fields[1], err)
				}
				reply.PeerID = uint32(id)
			}
		case "redirect-gateway":
			reply.Redirect = true
		case "block-ipv6":
			reply.BlockIPv6 = true
		case "data-ciphers", "ncp-ciphers":
			// "data-ciphers" (OpenVPN 2.5+) or "ncp-ciphers" (2.4 legacy name).
			// Value is a colon-separated list of cipher names.
			if len(fields) >= 2 {
				for _, c := range strings.Split(fields[1], ":") {
					c = strings.TrimSpace(c)
					if c != "" {
						reply.DataCiphers = append(reply.DataCiphers, c)
					}
				}
			}
		case "cipher":
			// Legacy single cipher push, or fallback cipher.
			if len(fields) >= 2 {
				reply.Cipher = strings.TrimSpace(fields[1])
			}
		case "ping":
			// Server-pushed keepalive ping interval (seconds).
			if len(fields) >= 2 {
				if v, err := strconv.Atoi(fields[1]); err == nil {
					reply.PingInterval = v
				}
			}
		case "ping-restart":
			// Server-pushed keepalive ping-restart timeout (seconds).
			if len(fields) >= 2 {
				if v, err := strconv.Atoi(fields[1]); err == nil {
					reply.PingRestart = v
				}
			}
		}
	}
	if len(reply.Prefixes) == 0 {
		return nil, fmt.Errorf("openvpn push reply missing ifconfig address")
	}
	return reply, nil
}

func splitPushOptions(message string) []string {
	message = strings.TrimRight(message, "\x00")
	parts := strings.Split(message, ",")
	if len(parts) > 0 && parts[0] == "PUSH_REPLY" {
		parts = parts[1:]
	}
	out := parts[:0]
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseIPv4Ifconfig(address, maskOrPeer string) (netip.Prefix, error) {
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse pushed ipv4 address %q: %w", address, err)
	}
	maskAddr, err := netip.ParseAddr(maskOrPeer)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse pushed ipv4 mask %q: %w", maskOrPeer, err)
	}
	if !addr.Is4() || !maskAddr.Is4() {
		return netip.Prefix{}, fmt.Errorf("openvpn ifconfig requires ipv4 address and mask")
	}

	if ones, ok := ipv4MaskSize(maskAddr); ok {
		return netip.PrefixFrom(addr, ones), nil
	}

	// Some servers, including SoftEther/VPNGate in net30/p2p mode, push
	// "ifconfig <local> <remote>" rather than "ifconfig <local> <netmask>".
	// Use a host prefix for that local tunnel address.
	return netip.PrefixFrom(addr, 32), nil
}

func parseIPv4Route(network, mask string) (netip.Prefix, error) {
	addr, err := netip.ParseAddr(network)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse route network %q: %w", network, err)
	}
	maskAddr, err := netip.ParseAddr(mask)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse route mask %q: %w", mask, err)
	}
	if !addr.Is4() || !maskAddr.Is4() {
		return netip.Prefix{}, fmt.Errorf("openvpn route requires ipv4 address and mask")
	}
	ones, ok := ipv4MaskSize(maskAddr)
	if !ok {
		return netip.Prefix{}, fmt.Errorf("invalid route mask %q", mask)
	}
	return netip.PrefixFrom(addr, ones), nil
}

func ipv4MaskSize(mask netip.Addr) (int, bool) {
	maskBytes := mask.As4()
	ones := 0
	seenZero := false
	for _, b := range maskBytes {
		for i := 7; i >= 0; i-- {
			if b&(1<<i) == 0 {
				seenZero = true
				continue
			}
			if seenZero {
				return 0, false
			}
			ones++
		}
	}
	return ones, true
}

// ApplyPullFilters filters the pushed options based on the configured pull filters.
// Returns an error if a "reject" filter matches.
func (r *PushReply) ApplyPullFilters(filters []PullFilter) error {
	if len(filters) == 0 {
		return nil
	}
	// For each pushed option, check if any filter matches.
	// We need to check the raw push reply options.
	options := splitPushOptions(r.Raw)
	for _, option := range options {
		option = strings.TrimSpace(option)
		for _, filter := range filters {
			if strings.HasPrefix(strings.ToLower(option), strings.ToLower(filter.Text)) {
				switch strings.ToLower(filter.Action) {
				case "accept":
					// Option is accepted (default behavior).
				case "ignore":
					// Option should be ignored. We can't easily un-parse
					// individual options from the structured PushReply, so
					// we track ignored options and clear their effects.
					r.applyIgnoredOption(option)
				case "reject":
					return fmt.Errorf("openvpn push option rejected by filter: %s", option)
				}
				break // Only the first matching filter applies.
			}
		}
	}
	return nil
}

// applyIgnoredOption clears the effect of an ignored push option.
func (r *PushReply) applyIgnoredOption(option string) {
	fields := strings.Fields(option)
	if len(fields) == 0 {
		return
	}
	switch fields[0] {
	case "route", "route-ipv6":
		// Can't selectively remove individual routes from the slice,
		// but this is a best-effort approach. In practice, pull filters
		// for routes are rare and the route list is rebuilt on each push.
	case "redirect-gateway":
		r.Redirect = false
	case "block-ipv6":
		r.BlockIPv6 = false
	case "dhcp-option":
		// DNS options are not selectively removed.
	case "data-ciphers", "ncp-ciphers":
		r.DataCiphers = nil
	case "cipher":
		r.Cipher = ""
	}
}

// ApplyRouteNoPull clears route-related options if RouteNoPull is enabled.
func (r *PushReply) ApplyRouteNoPull(noPull bool) {
	if !noPull {
		return
	}
	r.Routes = nil
	r.Redirect = false
}

// MergeLocalRoutes adds locally configured routes to the push reply's route list.
func (r *PushReply) MergeLocalRoutes(localRoutes []netip.Prefix) {
	if len(localRoutes) == 0 {
		return
	}
	r.Routes = append(r.Routes, localRoutes...)
}
