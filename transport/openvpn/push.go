package openvpn

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
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

	// AuthToken is the most recently pushed auth-token / auth-token-user
	// pair. Empty when the server does not rotate credentials.
	AuthTokenUser string
	AuthTokenPass string

	// PushContinuation mirrors OpenVPN's "push-continuation N": 2 marks an
	// intermediate multi-segment PUSH_REPLY, 1 marks the final segment, 0
	// means a single segment.
	PushContinuation int
	// HasPushReply distinguishes a parsed PUSH_REPLY from standalone control
	// metadata such as AUTH_PENDING carried in the same accumulator.
	HasPushReply bool

	// AuthPendingTimeout is the deferred-auth window advertised by
	// AUTH_PENDING,timeout N. Zero when no AUTH_PENDING was seen.
	AuthPendingTimeout time.Duration
	// authPendingUntil anchors that window to the TLS key establishment time,
	// matching OpenVPN key_state.established and preventing delayed messages or
	// later final PUSH_REPLY segments from restarting it.
	authPendingUntil time.Time
	// hasAuthPending distinguishes an explicit timeout of zero from no
	// AUTH_PENDING message.
	hasAuthPending bool
}

func ParsePushReply(message string) (*PushReply, error) {
	reply, err := parsePushReplyInner(message)
	if err != nil {
		return nil, err
	}
	if len(reply.Prefixes) == 0 {
		return nil, fmt.Errorf("openvpn push reply missing ifconfig address")
	}
	return reply, nil
}

func parsePushReplyInner(message string) (*PushReply, error) {
	message = strings.TrimRight(message, "\x00")
	if !strings.HasPrefix(message, "PUSH_REPLY") {
		return nil, fmt.Errorf("unexpected openvpn push message %q", message)
	}
	reply := &PushReply{
		Raw:          message,
		PeerID:       PeerIDUnset,
		HasPushReply: true,
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
			if len(fields) >= 2 {
				for _, c := range strings.Split(fields[1], ":") {
					c = strings.TrimSpace(c)
					if c != "" {
						reply.DataCiphers = append(reply.DataCiphers, c)
					}
				}
			}
		case "cipher":
			if len(fields) >= 2 {
				reply.Cipher = strings.TrimSpace(fields[1])
			}
		case "auth-token":
			if len(fields) >= 2 {
				reply.AuthTokenPass = strings.TrimSpace(fields[1])
			}
		case "auth-token-user":
			if len(fields) >= 2 {
				user, err := decodeAuthTokenUser(fields[1])
				if err != nil {
					return nil, fmt.Errorf("decode auth-token-user: %w", err)
				}
				reply.AuthTokenUser = user
			}
		case "push-continuation":
			if len(fields) != 2 {
				return nil, errors.New("invalid push-continuation")
			}
			n, err := strconv.Atoi(fields[1])
			if err != nil || n < 0 || n > 2 {
				return nil, fmt.Errorf("invalid push-continuation %q", fields[1])
			}
			reply.PushContinuation = n
		}
	}
	return reply, nil
}

func (p *PushReply) AuthToken() (user, pass string, ok bool) {
	if p == nil || p.AuthTokenPass == "" {
		return "", "", false
	}
	return p.AuthTokenUser, p.AuthTokenPass, true
}

func decodeAuthTokenUser(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	decoded, err := decodeBase64Auth(raw)
	if err != nil {
		return "", err
	}
	return decoded, nil
}

func decodeBase64Auth(raw string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(raw)
		if err != nil {
			return "", err
		}
	}
	return string(data), nil
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
