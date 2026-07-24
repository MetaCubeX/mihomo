// socks5_udp_test.go —— SOCKS5 UDP 头编解码 self-test(RFC 1928 §7)。
// 锁 parseSocks5UDP/encodeSocks5UDP round-trip + FRAG≠0 丢 + atype 映射(易踩坑 #2,SOCKS5↔speedcat 不同)。

package client

import (
	"bytes"
	"testing"

	"github.com/metacubex/mihomo/transport/speedcat/wire"
)

// TestSocks5UDPRoundTripIPv4 三 atype round-trip:encode→parse 须还原同 addr + data。
// 重点验 atype 映射(SOCKS5 domain=0x03 / IPv6=0x04 ↔ speedcat domain=0x02 / IPv6=0x03,易踩坑 #2)。
func TestSocks5UDPRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		addr wire.Addr
		data []byte
	}{
		{"ipv4", wire.Addr{Type: wire.AddrTypeIPv4, IPv4: [4]byte{8, 8, 8, 8}, Port: 53}, []byte("dns-q")},
		{"domain", wire.Addr{Type: wire.AddrTypeDomain, Domain: "example.com", Port: 443}, []byte("hello")},
		{"ipv6", wire.Addr{Type: wire.AddrTypeIPv6, IPv6: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, Port: 443}, []byte("v6")},
		{"empty-data", wire.Addr{Type: wire.AddrTypeIPv4, IPv4: [4]byte{1, 2, 3, 4}, Port: 80}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := encodeSocks5UDP(tc.addr, tc.data)
			// 头前三字节须 RSV=0/RSV=0/FRAG=0。
			if pkt[0] != 0 || pkt[1] != 0 || pkt[2] != 0 {
				t.Fatalf("RSV/FRAG 须 0, got %x %x %x", pkt[0], pkt[1], pkt[2])
			}
			gotAddr, gotData, ok := parseSocks5UDP(pkt)
			if !ok {
				t.Fatalf("parse 须 ok")
			}
			if gotAddr != tc.addr {
				t.Fatalf("addr 不一致: %+v != %+v", gotAddr, tc.addr)
			}
			if !bytes.Equal(gotData, tc.data) {
				t.Fatalf("data 不一致: %v != %v", gotData, tc.data)
			}
		})
	}
}

// TestSocks5UDPEncodeAtypMapping encode 出的 ATYP 须是 SOCKS5 取值(domain=0x03 / IPv6=0x04),非 speedcat。
// 这是易踩坑 #2 的直接锁:若误用 speedcat atype(0x02/0x03),真实 SOCKS5 客户端解析错。
func TestSocks5UDPEncodeAtypMapping(t *testing.T) {
	dom := encodeSocks5UDP(wire.Addr{Type: wire.AddrTypeDomain, Domain: "x", Port: 1}, nil)
	if dom[3] != socks5AtypDom { // SOCKS5 domain = 0x03(非 speedcat 0x02)
		t.Fatalf("domain ATYP 须 SOCKS5 0x%02x, got 0x%02x", socks5AtypDom, dom[3])
	}
	v6 := encodeSocks5UDP(wire.Addr{Type: wire.AddrTypeIPv6, IPv6: [16]byte{}, Port: 1}, nil)
	if v6[3] != socks5AtypIPv6 { // SOCKS5 IPv6 = 0x04(非 speedcat 0x03)
		t.Fatalf("ipv6 ATYP 须 SOCKS5 0x%02x, got 0x%02x", socks5AtypIPv6, v6[3])
	}
	v4 := encodeSocks5UDP(wire.Addr{Type: wire.AddrTypeIPv4, IPv4: [4]byte{}, Port: 1}, nil)
	if v4[3] != socks5AtypIPv4 { // 两协议 IPv4 同 0x01
		t.Fatalf("ipv4 ATYP 须 0x%02x, got 0x%02x", socks5AtypIPv4, v4[3])
	}
}

// TestSocks5UDPParseRejectsFRAG FRAG≠0 → ok=false(SOCKS5 层分片不支持,丢;RFC 1928 §7)。
func TestSocks5UDPParseRejectsFRAG(t *testing.T) {
	pkt := encodeSocks5UDP(wire.Addr{Type: wire.AddrTypeIPv4, IPv4: [4]byte{1, 2, 3, 4}, Port: 53}, []byte("x"))
	pkt[2] = 0x01 // FRAG=1(分片)
	if _, _, ok := parseSocks5UDP(pkt); ok {
		t.Fatal("FRAG≠0 须被丢(ok=false)")
	}
}

// TestSocks5UDPParseRejectsMalformed RSV≠0 / 截断 / 未知 ATYP → ok=false(丢畸形包)。
func TestSocks5UDPParseRejectsMalformed(t *testing.T) {
	// RSV≠0。
	pkt := encodeSocks5UDP(wire.Addr{Type: wire.AddrTypeIPv4, IPv4: [4]byte{1, 2, 3, 4}, Port: 53}, []byte("x"))
	pkt[0] = 0x01
	if _, _, ok := parseSocks5UDP(pkt); ok {
		t.Fatal("RSV≠0 须被丢")
	}
	// 截断(< 4B)。
	if _, _, ok := parseSocks5UDP([]byte{0, 0, 0}); ok {
		t.Fatal("截断须被丢")
	}
	// IPv4 声明但 body 不足 4+2。
	if _, _, ok := parseSocks5UDP([]byte{0, 0, 0, socks5AtypIPv4, 1, 2}); ok {
		t.Fatal("IPv4 body 不足须被丢")
	}
	// 未知 ATYP。
	if _, _, ok := parseSocks5UDP([]byte{0, 0, 0, 0x07}); ok {
		t.Fatal("未知 ATYP 须被丢")
	}
}
