package cidr

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

type shortIPReader struct{ io.Reader }

func (r shortIPReader) Read(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return r.Reader.Read(p)
}

func cidrBinaryFixture(tb testing.TB, count int) (*IpCidrSet, []byte) {
	tb.Helper()
	set := NewIpCidrSet()
	for i := 0; i < count; i++ {
		set.AddIpCidrForString(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
	}
	set.AddIpCidrForString("2001:db8::/32")
	var out bytes.Buffer
	if err := set.WriteBin(&out); err != nil {
		tb.Fatal(err)
	}
	return set, out.Bytes()
}

func TestIPBinaryMemoryRoundTrip(t *testing.T) {
	want, data := cidrBinaryFixture(t, 5)
	for _, short := range []bool{false, true} {
		input := bytes.NewReader(append(append([]byte{}, data...), 0xde, 0xad))
		var r io.Reader = input
		if short {
			r = shortIPReader{input}
		}
		got, err := ReadIpCidrSet(r)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err = got.WriteBin(&out); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, out.Bytes()) || input.Len() != 2 {
			t.Fatal("binary format or reader boundary changed")
		}
		for _, ip := range []string{"10.0.2.1", "10.1.2.1", "2001:db8::123", "2001:db9::1"} {
			if got.IsContainForString(ip) != want.IsContainForString(ip) {
				t.Fatalf("lookup changed: %s", ip)
			}
		}
	}
	for n := 0; n < len(data); n++ {
		if _, err := ReadIpCidrSet(shortIPReader{bytes.NewReader(data[:n])}); err == nil {
			t.Fatalf("accepted truncated input at %d", n)
		}
	}
}

func BenchmarkIPBinaryReadMemory(b *testing.B) {
	_, data := cidrBinaryFixture(b, 10000)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ReadIpCidrSet(bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}
