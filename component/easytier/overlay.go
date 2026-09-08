package easytier

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

const DefaultTLDDNSZone = "et.net."

// Node describes one overlay IPv4 hostname mapping.
type Node struct {
	Hostname string
	IPv4     netip.Addr
}

// NormalizeDNSName lowercases a name and strips a trailing dot.
func NormalizeDNSName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// NormalizeZone returns a MagicDNS zone without a trailing dot.
func NormalizeZone(zone string) string {
	zone = NormalizeDNSName(zone)
	if zone == "" {
		return NormalizeDNSName(DefaultTLDDNSZone)
	}
	return zone
}

// OverlayNames returns hostname forms that MagicDNS may use.
func OverlayNames(hostname, zone string) []string {
	hostname = NormalizeDNSName(hostname)
	if hostname == "" {
		return nil
	}
	zone = NormalizeZone(zone)
	names := []string{hostname}
	if hostname != zone && !strings.HasSuffix(hostname, "."+zone) {
		names = append(names, hostname+"."+zone)
	}
	return names
}

// IsMagicDNS reports whether host should stay on the overlay resolver.
func IsMagicDNS(host, zone string) bool {
	host = NormalizeDNSName(host)
	if host == "" {
		return false
	}
	zone = NormalizeZone(zone)
	return host == zone || strings.HasSuffix(host, "."+zone)
}

// LookupOverlayHost finds an overlay IPv4 address for host.
func LookupOverlayHost(host, zone string, nodes []Node) (netip.Addr, bool) {
	host = NormalizeDNSName(host)
	if host == "" {
		return netip.Addr{}, false
	}
	for _, node := range nodes {
		if !node.IPv4.IsValid() || !node.IPv4.Is4() {
			continue
		}
		for _, name := range OverlayNames(node.Hostname, zone) {
			if host == name {
				return node.IPv4, true
			}
		}
	}
	return netip.Addr{}, false
}

// LookupOverlayPTR finds a MagicDNS name for an overlay IPv4 address.
func LookupOverlayPTR(ip netip.Addr, zone string, nodes []Node) (string, bool) {
	if !ip.IsValid() || !ip.Is4() {
		return "", false
	}
	zone = NormalizeZone(zone)
	for _, node := range nodes {
		if node.IPv4 != ip {
			continue
		}
		names := OverlayNames(node.Hostname, zone)
		if len(names) == 0 {
			continue
		}
		return names[len(names)-1] + ".", true
	}
	return "", false
}

// ParseNodeIPv4 parses a node IPv4 address or CIDR such as "10.144.0.1/24".
func ParseNodeIPv4(value string) (netip.Addr, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Addr{}, fmt.Errorf("easytier: empty overlay IPv4 address")
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Addr().Unmap(), nil
	}
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, err
	}
	return ip.Unmap(), nil
}

// IPv4FromUint32 converts a big-endian IPv4 integer to an address.
func IPv4FromUint32(addr uint32) netip.Addr {
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], addr)
	return netip.AddrFrom4(bytes)
}

// ParsePTRIPv4 parses an IPv4 PTR name such as "2.0.144.10.in-addr.arpa.".
func ParsePTRIPv4(name string) (netip.Addr, bool) {
	name = NormalizeDNSName(name)
	const suffix = ".in-addr.arpa"
	if !strings.HasSuffix(name, suffix) {
		return netip.Addr{}, false
	}
	labels := strings.Split(strings.TrimSuffix(name, suffix), ".")
	if len(labels) != 4 {
		return netip.Addr{}, false
	}
	var bytes [4]byte
	for i := 0; i < 4; i++ {
		part, err := strconv.Atoi(labels[3-i])
		if err != nil || part < 0 || part > 255 {
			return netip.Addr{}, false
		}
		bytes[i] = byte(part)
	}
	return netip.AddrFrom4(bytes), true
}
