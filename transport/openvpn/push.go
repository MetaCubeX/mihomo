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
	DNS       []netip.Addr
	PeerID    uint32
	Redirect  bool
	BlockIPv6 bool
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

func parseIPv4Ifconfig(address, mask string) (netip.Prefix, error) {
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse pushed ipv4 address %q: %w", address, err)
	}
	maskAddr, err := netip.ParseAddr(mask)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse pushed ipv4 mask %q: %w", mask, err)
	}
	if !addr.Is4() || !maskAddr.Is4() {
		return netip.Prefix{}, fmt.Errorf("openvpn ifconfig requires ipv4 address and mask")
	}
	maskBytes := maskAddr.As4()
	ones := 0
	for _, b := range maskBytes {
		for i := 7; i >= 0; i-- {
			if b&(1<<i) == 0 {
				return netip.PrefixFrom(addr, ones), nil
			}
			ones++
		}
	}
	return netip.PrefixFrom(addr, ones), nil
}
