package provider

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/klauspost/compress/zstd"
)

func mrsMemoryFixture(tb testing.TB, count int) ([]byte, []byte) {
	tb.Helper()
	strategy := NewDomainStrategy()
	for i := 0; i < count; i++ {
		strategy.Insert(fmt.Sprintf("+.node-%d.example.com", i))
	}
	strategy.FinishInsert()
	var raw bytes.Buffer
	raw.Write(MrsMagicBytes[:])
	raw.WriteByte(strategy.Behavior().Byte())
	binary.Write(&raw, binary.BigEndian, int64(strategy.Count()))
	binary.Write(&raw, binary.BigEndian, int64(0))
	if err := strategy.WriteMrs(&raw); err != nil {
		tb.Fatal(err)
	}
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderCRC(true))
	if err != nil {
		tb.Fatal(err)
	}
	defer encoder.Close()
	return encoder.EncodeAll(raw.Bytes(), nil), raw.Bytes()
}

func TestMrsMemoryDecoderCompatibility(t *testing.T) {
	for _, count := range []int{1, 50000} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			data, raw := mrsMemoryFixture(t, count)
			got, err := rulesMrsParse(data, NewDomainStrategy())
			if err != nil {
				t.Fatal(err)
			}
			reference := NewDomainStrategy()
			if err = reference.FromMrs(bytes.NewReader(raw[21:]), count); err != nil {
				t.Fatal(err)
			}
			if got.Count() != reference.Count() {
				t.Fatal("count changed")
			}
			for _, host := range []string{"node-0.example.com", "www.node-0.example.com", "node-60000.example.com", "example.com"} {
				metadata := &C.Metadata{Host: host}
				if got.Match(metadata, C.RuleMatchHelper{}) != reference.Match(metadata, C.RuleMatchHelper{}) {
					t.Fatalf("lookup changed: %s", host)
				}
			}
			// Last four bytes are the zstd frame checksum. A complete rule payload
			// must still reject a damaged or truncated frame after synchronous decoding.
			broken := append([]byte{}, data...)
			broken[len(broken)-1] ^= 1
			if _, err = rulesMrsParse(broken, NewDomainStrategy()); err == nil {
				t.Fatal("accepted invalid zstd checksum")
			}
			for _, n := range []int{0, 1, 4, len(data) / 2, len(data) - 4, len(data) - 1} {
				if _, err = rulesMrsParse(data[:n], NewDomainStrategy()); err == nil {
					t.Fatalf("accepted truncated frame at %d", n)
				}
			}
		})
	}
}

func BenchmarkMrsReadMemory(b *testing.B) {
	data, _ := mrsMemoryFixture(b, 50000)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := rulesMrsParse(data, NewDomainStrategy()); err != nil {
			b.Fatal(err)
		}
	}
}

func TestMrsIPMemoryDecoderCompatibility(t *testing.T) {
	strategy := NewIPCidrStrategy()
	strategy.Reset()
	for _, prefix := range []string{"10.0.0.0/24", "192.0.2.0/24", "2001:db8::/32"} {
		strategy.Insert(prefix)
	}
	strategy.FinishInsert()
	var raw bytes.Buffer
	raw.Write(MrsMagicBytes[:])
	raw.WriteByte(strategy.Behavior().Byte())
	binary.Write(&raw, binary.BigEndian, int64(strategy.Count()))
	binary.Write(&raw, binary.BigEndian, int64(0))
	if err := strategy.WriteMrs(&raw); err != nil {
		t.Fatal(err)
	}
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderCRC(true))
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	data := encoder.EncodeAll(raw.Bytes(), nil)
	got, err := rulesMrsParse(data, NewIPCidrStrategy())
	if err != nil {
		t.Fatal(err)
	}
	if got.Count() != strategy.Count() {
		t.Fatal("count changed")
	}
	for _, ip := range []string{"10.0.0.1", "10.0.1.1", "192.0.2.1", "2001:db8::1", "2001:db9::1"} {
		metadata := &C.Metadata{DstIP: netip.MustParseAddr(ip)}
		if got.Match(metadata, C.RuleMatchHelper{}) != strategy.Match(metadata, C.RuleMatchHelper{}) {
			t.Fatalf("lookup changed: %s", ip)
		}
	}
	broken := append([]byte{}, data...)
	broken[len(broken)-1] ^= 1
	if _, err := rulesMrsParse(broken, NewIPCidrStrategy()); err == nil {
		t.Fatal("accepted invalid zstd checksum")
	}
	for _, n := range []int{0, 1, 4, len(data) / 2, len(data) - 4, len(data) - 1} {
		if _, err := rulesMrsParse(data[:n], NewIPCidrStrategy()); err == nil {
			t.Fatalf("accepted truncated IP frame at %d", n)
		}
	}
}
