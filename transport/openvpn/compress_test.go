package openvpn

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseCompressionMode(t *testing.T) {
	tests := []struct {
		input string
		want  CompressionMode
		err   bool
	}{
		{"", CompressionNone, false}, {"off", CompressionNone, false},
		{"disabled", CompressionNone, false}, {"none", CompressionNone, false},
		{"no", CompressionStub, false}, {"stub", CompressionStub, false},
		{"stub-v2", CompressionStubV2, false}, {"lz4", CompressionLZ4, false},
		{"lz4-v2", CompressionLZ4v2, false}, {"invalid", CompressionNone, true},
	}
	for _, tc := range tests {
		got, err := ParseCompressionMode(tc.input)
		if (err != nil) != tc.err || (!tc.err && got != tc.want) {
			t.Fatalf("ParseCompressionMode(%q) = %v, %v", tc.input, got, err)
		}
	}
}

func TestParseAllowCompression(t *testing.T) {
	for input, want := range map[string]AllowCompressionPolicy{
		"": AllowCompressionNo, "no": AllowCompressionNo,
		"asym": AllowCompressionAsym, "yes": AllowCompressionYes,
	} {
		got, err := ParseAllowCompression(input)
		if err != nil || got != want {
			t.Fatalf("ParseAllowCompression(%q) = %v, %v", input, got, err)
		}
	}
}

func TestCompressorStubV1RoundTrip(t *testing.T) {
	c := NewCompressor(CompressionStub, AllowCompressionNo)
	original := []byte{0x45, 1, 2, 3, 4}
	framed, err := c.CompressFrame(original)
	if err != nil {
		t.Fatal(err)
	}
	if framed[0] != openVPNNoCompressByteSwap || framed[len(framed)-1] != original[0] {
		t.Fatalf("invalid v1 swap frame: %x", framed)
	}
	got, err := c.DecompressFrame(framed)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("round trip = %x, %v", got, err)
	}
}

func TestCompressorStubV2PassThroughAndEscape(t *testing.T) {
	c := NewCompressor(CompressionStubV2, AllowCompressionNo)
	plain := []byte{0x45, 1, 2}
	framed, _ := c.CompressFrame(plain)
	if !bytes.Equal(framed, plain) {
		t.Fatalf("non-0x50 payload should pass through: %x", framed)
	}
	got, err := c.DecompressFrame(framed)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("pass-through decode = %x, %v", got, err)
	}

	escapedSource := []byte{openVPNCompressV2Byte, 1, 2}
	escaped, _ := c.CompressFrame(escapedSource)
	wantPrefix := []byte{openVPNCompressV2Byte, openVPNCompressV2None}
	if !bytes.HasPrefix(escaped, wantPrefix) {
		t.Fatalf("invalid v2 escape: %x", escaped)
	}
	got, err = c.DecompressFrame(escaped)
	if err != nil || !bytes.Equal(got, escapedSource) {
		t.Fatalf("escaped decode = %x, %v", got, err)
	}
}

func TestCompressorLZ4V1RealCompressionRoundTrip(t *testing.T) {
	c := NewCompressor(CompressionLZ4, AllowCompressionYes)
	original := bytes.Repeat([]byte("openvpn-lz4-v1-"), 200)
	framed, err := c.CompressFrame(original)
	if err != nil {
		t.Fatal(err)
	}
	if framed[0] != openVPNLZ4CompressByte {
		t.Fatalf("expected compressed marker 0x69, got %x", framed[:1])
	}
	got, err := c.DecompressFrame(framed)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("round trip failed: len=%d err=%v", len(got), err)
	}
}

func TestCompressorLZ4V2RealCompressionRoundTrip(t *testing.T) {
	c := NewCompressor(CompressionLZ4v2, AllowCompressionYes)
	original := bytes.Repeat([]byte("openvpn-lz4-v2-"), 200)
	framed, err := c.CompressFrame(original)
	if err != nil {
		t.Fatal(err)
	}
	if len(framed) < 2 || framed[0] != openVPNCompressV2Byte || framed[1] != openVPNCompressV2LZ4 {
		t.Fatalf("expected v2 compressed header, got %x", framed)
	}
	got, err := c.DecompressFrame(framed)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("round trip failed: len=%d err=%v", len(got), err)
	}
}

func TestCompressorLZ4RejectsCompressedWhenForbidden(t *testing.T) {
	producer := NewCompressor(CompressionLZ4v2, AllowCompressionYes)
	consumer := NewCompressor(CompressionLZ4v2, AllowCompressionNo)
	framed, err := producer.CompressFrame(bytes.Repeat([]byte("compress-me"), 200))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = consumer.DecompressFrame(framed); err == nil {
		t.Fatal("expected compressed payload rejection")
	}
}

func TestBuildCompressor(t *testing.T) {
	if c := (ClientConfig{Compression: "stub-v2"}).buildCompressor(); c == nil || c.Mode() != CompressionStubV2 {
		t.Fatal("stub-v2 compressor missing")
	}
	if c := (ClientConfig{CompLZO: CompLzoYes}).buildCompressor(); c == nil || c.Mode() != CompressionLZO {
		t.Fatal("LZO compressor missing")
	}
	if c := (ClientConfig{}).buildCompressor(); c != nil {
		t.Fatal("unexpected compressor")
	}
}

func TestInstallScriptPeerInfoCompressionFlags(t *testing.T) {
	v2 := InstallScriptPeerInfo(CipherAES128GCM, nil, "", "stub-v2", nil)
	if !strings.Contains(v2, "IV_COMP_STUB=1") || !strings.Contains(v2, "IV_COMP_STUBv2=1") {
		t.Fatalf("missing v2 flags: %q", v2)
	}
	v1 := InstallScriptPeerInfo(CipherAES128GCM, nil, "", "stub", nil)
	if !strings.Contains(v1, "IV_COMP_STUB=1") || strings.Contains(v1, "IV_COMP_STUBv2") {
		t.Fatalf("wrong v1 flags: %q", v1)
	}
}
