package trie

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

type shortDomainReader struct{ io.Reader }

func (r shortDomainReader) Read(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return r.Reader.Read(p)
}

func domainBinaryFixture(tb testing.TB, count int) (*DomainSet, []byte) {
	tb.Helper()
	var builder DomainSetBuilder
	for i := 0; i < count; i++ {
		if err := builder.Insert(fmt.Sprintf("+.node-%d.example.com", i)); err != nil {
			tb.Fatal(err)
		}
	}
	set := builder.Build()
	var buf bytes.Buffer
	if err := set.WriteBin(&buf); err != nil {
		tb.Fatal(err)
	}
	return set, buf.Bytes()
}

func TestDomainBinaryMemoryRoundTrip(t *testing.T) {
	want, data := domainBinaryFixture(t, 12)
	for _, short := range []bool{false, true} {
		input := bytes.NewReader(append(append([]byte{}, data...), 0xde, 0xad))
		var r io.Reader = input
		if short {
			r = shortDomainReader{input}
		}
		got, err := ReadDomainSetBin(r)
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
		for _, host := range []string{"node-3.example.com", "www.node-3.example.com", "node-99.example.com", "example.com"} {
			if got.Has(host) != want.Has(host) {
				t.Fatalf("lookup changed: %s", host)
			}
		}
	}
	for n := 0; n < len(data); n++ {
		if _, err := ReadDomainSetBin(shortDomainReader{bytes.NewReader(data[:n])}); err == nil {
			t.Fatalf("accepted truncated input at %d", n)
		}
	}
}

func BenchmarkDomainBinaryReadMemory(b *testing.B) {
	_, data := domainBinaryFixture(b, 10000)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ReadDomainSetBin(bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}
