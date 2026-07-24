package wire

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// 对照 docs/02 §5 + Rust Addr 编码,table-driven round-trip + 固定向量。
func TestAddrMarshalRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		addr Addr
	}{
		{"ipv4", Addr{Type: AddrTypeIPv4, IPv4: [4]byte{1, 2, 3, 4}, Port: 443}},
		{"ipv6", Addr{Type: AddrTypeIPv6, IPv6: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, Port: 8443}},
		{"domain", Addr{Type: AddrTypeDomain, Domain: "example.com", Port: 80}},
		{"domain-empty", Addr{Type: AddrTypeDomain, Domain: "", Port: 0}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := c.addr.MarshalBinary()
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			got, n, err := DecodeAddr(b)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if n != len(b) {
				t.Fatalf("consumed %d, want %d", n, len(b))
			}
			if got != c.addr {
				t.Fatalf("got %+v, want %+v", got, c.addr)
			}
		})
	}
}

// 固定向量:atype 0x01 + IPv4(4) + port:BE(2)。1.2.3.4:443 = 01 01020304 01BB(02 §5)。
func TestAddrFixedVectorIPv4(t *testing.T) {
	a := Addr{Type: AddrTypeIPv4, IPv4: [4]byte{1, 2, 3, 4}, Port: 443}
	b, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("0101020304" + "01bb")
	if !bytes.Equal(b, want) {
		t.Fatalf("got %x, want %x", b, want)
	}
}

// 固定向量:atype 0x02 + len(1) + domain + port:BE(2)。example.com:80(02 §5)。
func TestAddrFixedVectorDomain(t *testing.T) {
	a := Addr{Type: AddrTypeDomain, Domain: "example.com", Port: 80}
	b, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x02, 11}
	want = append(want, []byte("example.com")...)
	want = append(want, 0x00, 0x50)
	if !bytes.Equal(b, want) {
		t.Fatalf("got %x, want %x", b, want)
	}
}

func TestAddrDomainTooLong(t *testing.T) {
	a := Addr{Type: AddrTypeDomain, Domain: string(make([]byte, 256)), Port: 1}
	if _, err := a.MarshalBinary(); err == nil {
		t.Fatal("want error for >255 domain")
	}
}

func TestAddrUnknownType(t *testing.T) {
	a := Addr{Type: 0x42}
	if _, err := a.MarshalBinary(); err == nil {
		t.Fatal("want error for unknown type")
	}
}

func TestAddrReadStreaming(t *testing.T) {
	a := Addr{Type: AddrTypeDomain, Domain: "hk.example.com", Port: 8443}
	b, _ := a.MarshalBinary()
	got, err := ReadAddr(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if got != a {
		t.Fatalf("got %+v want %+v", got, a)
	}
}

func TestAddrTruncated(t *testing.T) {
	if _, _, err := DecodeAddr([]byte{0x01, 1, 2}); err == nil {
		t.Fatal("want truncation error")
	}
}
