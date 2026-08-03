package tls_test

import (
	"bytes"
	"testing"

	tlsC "github.com/metacubex/mihomo/component/tls"
)

func TestParseClientVersion(t *testing.T) {
	defaultVersion := []byte{1, 8, 2}
	testCases := []struct {
		version string
		want    []byte
	}{
		{"26.3.27", []byte{26, 3, 27}},
		{"1.8.2", []byte{1, 8, 2}},
		{"", defaultVersion},
		{"26.3", defaultVersion},
		{"26.3.27.1", defaultVersion},
		{"a.b.c", defaultVersion},
		{"26.3.-1", defaultVersion},
		{"26.3.256", defaultVersion},
	}
	for _, tc := range testCases {
		got := tlsC.ParseClientVersion(tc.version)
		if !bytes.Equal(got, tc.want) {
			t.Fatalf("ParseClientVersion(%q) = %v, want %v", tc.version, got, tc.want)
		}
	}
}
