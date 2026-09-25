//go:build windows && (amd64 || 386)

package windivert

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"

	"github.com/metacubex/sing/common/ranges"
)

// Field/test values follow the WinDivert 2.2 ABI (include/windivert_device.h).
type filterExpr struct {
	field, test uint32
	arg         [4]uint32
	children    []filterExpr
	or          bool
}

func filterEqual(field, value uint32) filterExpr {
	return filterExpr{field: field, arg: [4]uint32{value}}
}
func filterAll(children ...filterExpr) filterExpr {
	if children == nil {
		children = []filterExpr{}
	}
	return filterExpr{children: children}
}
func filterAny(children ...filterExpr) filterExpr {
	if children == nil {
		children = []filterExpr{}
	}
	return filterExpr{children: children, or: true}
}
func filterNot(expr filterExpr) filterExpr {
	if expr.children != nil {
		expr.or = !expr.or
		for i := range expr.children {
			expr.children[i] = filterNot(expr.children[i])
		}
	} else {
		switch expr.test {
		case 0:
			expr.test = 1
		case 1:
			expr.test = 0
		case 2:
			expr.test = 5
		case 3:
			expr.test = 4
		case 4:
			expr.test = 3
		case 5:
			expr.test = 2
		}
	}
	return expr
}

func filterIP(field uint32, ip netip.Addr, test uint32) filterExpr {
	// The interpreter compares four host-order words, least significant first.
	// IPv4 operands are represented as IPv4-mapped IPv6, including word 1.
	ipBytes := ip.As16()
	var arg [4]uint32
	for i := range arg {
		arg[3-i] = binary.BigEndian.Uint32(ipBytes[4*i:])
	}
	return filterExpr{field: field, test: test, arg: arg}
}

func filterPrefix(prefix netip.Prefix) filterExpr {
	first := prefix.Masked().Addr()
	last := first.As16()
	bits := prefix.Bits()
	field, family := uint32(29), uint32(6)
	if first.Is4() {
		bits += 96
		field, family = 22, 5
	}
	for bit := bits; bit < 128; bit++ {
		last[bit/8] |= 1 << (7 - bit%8)
	}
	end := netip.AddrFrom16(last)
	if first.Is4() {
		end = end.Unmap()
	}
	return filterAll(filterEqual(family, 1), filterIP(field, first, 5), filterIP(field, end, 3))
}

func filterPrefixes(prefixes []netip.Prefix) filterExpr {
	children := make([]filterExpr, 0, len(prefixes))
	for _, prefix := range prefixes {
		children = append(children, filterPrefix(prefix))
	}
	return filterAny(children...)
}

func filterInterfaces(indexes map[uint32]bool) filterExpr {
	keys := make([]int, 0, len(indexes))
	for index := range indexes {
		keys = append(keys, int(index))
	}
	sort.Ints(keys)
	children := make([]filterExpr, 0, len(keys))
	for _, key := range keys {
		children = append(children, filterEqual(3, uint32(key)))
	}
	return filterAny(children...)
}

func filterPorts(ports []uint16, intervals []ranges.Range[uint16], source bool) filterExpr {
	tcpField, udpField := uint32(39), uint32(54)
	if source {
		tcpField, udpField = 38, 53
	}
	var protocols []filterExpr
	for i, field := range []uint32{tcpField, udpField} {
		var children []filterExpr
		for _, port := range ports {
			children = append(children, filterEqual(field, uint32(port)))
		}
		for _, interval := range intervals {
			low, high := filterEqual(field, uint32(interval.Start)), filterEqual(field, uint32(interval.End))
			low.test, high.test = 5, 3
			children = append(children, filterAll(low, high))
		}
		protocols = append(protocols, filterAll(filterEqual(uint32(8+i), 1), filterAny(children...)))
	}
	return filterAny(protocols...)
}

func filterDNS(targets []netip.AddrPort) filterExpr {
	children := make([]filterExpr, 0, len(targets))
	for _, target := range targets {
		if target.Addr().IsUnspecified() {
			// Match ListenerHandler.ShouldHijackDns wildcard semantics.
			children = append(children, filterPorts([]uint16{53}, nil, false))
			continue
		}
		field := uint32(29)
		if target.Addr().Is4() {
			field = 22
		}
		children = append(children, filterAll(filterIP(field, target.Addr(), 0), filterPorts([]uint16{target.Port()}, nil, false)))
	}
	return filterAny(children...)
}

func (t *Tun) networkFilter() ([]instruction, error) {
	selected := []filterExpr{filterEqual(58, 0), filterAny(filterEqual(8, 1), filterEqual(9, 1))}
	// Capture global unicast destinations.
	var bypass []netip.Prefix
	for _, prefix := range []string{"0.0.0.0/32", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "::/128", "::1/128", "fe80::/10", "ff00::/8"} {
		bypass = append(bypass, netip.MustParsePrefix(prefix))
	}
	selected = append(selected, filterNot(filterPrefixes(bypass)))
	if len(t.includeIf) > 0 {
		selected = append(selected, filterInterfaces(t.includeIf))
	}
	if len(t.excludeIf) > 0 {
		selected = append(selected, filterNot(filterInterfaces(t.excludeIf)))
	}
	if len(t.options.ExcludeSrcPort)+len(t.options.ExcludeSrcPortRange) > 0 {
		selected = append(selected, filterNot(filterPorts(t.options.ExcludeSrcPort, t.options.ExcludeSrcPortRange, true)))
	}
	if len(t.options.ExcludeDstPort)+len(t.options.ExcludeDstPortRange) > 0 {
		selected = append(selected, filterNot(filterPorts(t.options.ExcludeDstPort, t.options.ExcludeDstPortRange, false)))
	}
	var routed []filterExpr
	if !t.options.IPv6 {
		routed = append(routed, filterEqual(5, 1))
	}
	if len(t.options.RouteAddress) > 0 {
		routed = append(routed, filterPrefixes(t.options.RouteAddress))
	}
	if len(t.options.ExcludeAddress) > 0 {
		routed = append(routed, filterNot(filterPrefixes(t.options.ExcludeAddress)))
	}
	if len(t.options.HijackDNS) > 0 && len(routed) > 0 {
		// DNS targets bypass proxy address restrictions.
		selected = append(selected, filterAny(filterDNS(t.options.HijackDNS), filterAll(routed...)))
	} else {
		selected = append(selected, routed...)
	}
	expr := filterAll(selected...)
	if t.tcp != nil {
		var replies []filterExpr
		for _, ip := range []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1}), netip.IPv6Loopback()} {
			if t.tcp.port(ip) == 0 {
				continue
			}
			srcField, dstField, family := uint32(21), uint32(22), uint32(5)
			if ip.Is6() {
				srcField, dstField, family = 28, 29, 6
			}
			replies = append(replies, filterAll(filterEqual(family, 1), filterEqual(38, uint32(t.tcp.port(ip))), filterIP(srcField, relayLocal(ip), 0), filterIP(dstField, relayPeer(ip), 0)))
		}
		expr = filterAny(filterAll(filterEqual(58, 1), filterEqual(8, 1), filterAny(replies...)), expr)
	}
	expr = filterAll(filterEqual(2, 1), filterEqual(59, 0), filterEqual(85, 0), expr)
	if expr.size() > 256 {
		return nil, fmt.Errorf("WFP filter requires %d instructions (WinDivert limit: 256); simplify route/interface/port rules", expr.size())
	}
	var code []instruction
	expr.compile(&code, accept, reject)
	return code, nil
}

func (e filterExpr) size() int {
	if len(e.children) == 0 {
		return 1
	}
	n := 0
	for _, child := range e.children {
		n += child.size()
	}
	return n
}

func (e filterExpr) compile(code *[]instruction, yes, no uint16) {
	if len(e.children) == 0 {
		if e.children != nil {
			isOr := e.or
			e = filterEqual(0, 0)
			if isOr {
				e.arg[0] = 1
			}
		}
		*code = append(*code, instruction{FieldTestSuccess: e.field | e.test<<11 | uint32(yes)<<16, Failure: uint32(no), Arg: e.arg})
		return
	}
	for i, child := range e.children {
		nextYes, nextNo := yes, no
		if i+1 < len(e.children) {
			next := uint16(len(*code) + child.size())
			if e.or {
				nextNo = next
			} else {
				nextYes = next
			}
		}
		child.compile(code, nextYes, nextNo)
	}
}
