package openvpn

import (
	"testing"
)

func TestParseCompressionMode(t *testing.T) {
	tests := []struct {
		input string
		want  CompressionMode
		err   bool
	}{
		{"", CompressionNone, false},
		{"off", CompressionNone, false},
		{"disabled", CompressionNone, false},
		{"none", CompressionNone, false},
		{"no", CompressionStub, false},
		{"stub", CompressionStub, false},
		{"stub-v2", CompressionStubV2, false},
		{"lz4", CompressionLZ4, false},
		{"lz4-v2", CompressionLZ4v2, false},
		{"STUB", CompressionStub, false},
		{"invalid", CompressionNone, true},
	}
	for _, tc := range tests {
		got, err := ParseCompressionMode(tc.input)
		if tc.err {
			if err == nil {
				t.Errorf("ParseCompressionMode(%q) expected error, got none", tc.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseCompressionMode(%q) unexpected error: %v", tc.input, err)
		}
		if got != tc.want {
			t.Errorf("ParseCompressionMode(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestParseAllowCompression(t *testing.T) {
	tests := []struct {
		input string
		want  AllowCompressionPolicy
	}{
		{"", AllowCompressionNo},
		{"no", AllowCompressionNo},
		{"asym", AllowCompressionAsym},
		{"yes", AllowCompressionYes},
	}
	for _, tc := range tests {
		got, _ := ParseAllowCompression(tc.input)
		if got != tc.want {
			t.Errorf("ParseAllowCompression(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestCompressorStubRoundTrip(t *testing.T) {
	c := NewCompressor(CompressionStub, AllowCompressionNo)
	original := []byte("hello world")
	framed, err := c.CompressFrame(original)
	if err != nil {
		t.Fatal(err)
	}
	if framed[0] != compressByteStub {
		t.Fatalf("expected stub byte 0x50, got 0x%02x", framed[0])
	}
	unframed, err := c.DecompressFrame(framed)
	if err != nil {
		t.Fatal(err)
	}
	if string(unframed) != string(original) {
		t.Fatalf("round-trip mismatch: got %q, want %q", unframed, original)
	}
}

func TestCompressorStubV2RoundTrip(t *testing.T) {
	c := NewCompressor(CompressionStubV2, AllowCompressionNo)

	// Normal packet.
	original := []byte("hello world")
	framed, err := c.CompressFrame(original)
	if err != nil {
		t.Fatal(err)
	}
	unframed, err := c.DecompressFrame(framed)
	if err != nil {
		t.Fatal(err)
	}
	if string(unframed) != string(original) {
		t.Fatalf("round-trip mismatch: got %q, want %q", unframed, original)
	}

	// Packet starting with 0x00 (requires extra byte).
	originalZero := []byte{0x00, 0x01, 0x02}
	framedZero, err := c.CompressFrame(originalZero)
	if err != nil {
		t.Fatal(err)
	}
	// Should have the stub byte + an extra 0x00 + the original 0x00, 0x01, 0x02.
	if framedZero[0] != compressByteStub {
		t.Fatalf("expected stub byte 0x50, got 0x%02x", framedZero[0])
	}
	if framedZero[1] != 0x00 {
		t.Fatalf("expected disambiguation byte 0x00, got 0x%02x", framedZero[1])
	}
	unframedZero, err := c.DecompressFrame(framedZero)
	if err != nil {
		t.Fatal(err)
	}
	if string(unframedZero) != string(originalZero) {
		t.Fatalf("zero-prefix round-trip mismatch: got %v, want %v", unframedZero, originalZero)
	}
}

func TestCompressorNone(t *testing.T) {
	c := NewCompressor(CompressionNone, AllowCompressionNo)
	original := []byte("hello")
	framed, err := c.CompressFrame(original)
	if err != nil {
		t.Fatal(err)
	}
	if string(framed) != string(original) {
		t.Fatalf("CompressionNone should not modify packet")
	}
}

func TestCompressorLZ4UncompressedFraming(t *testing.T) {
	// LZ4 mode with allow-compression=yes sends uncompressed framing when
	// actual LZ4 compression is not implemented.
	c := NewCompressor(CompressionLZ4, AllowCompressionYes)
	original := []byte("hello lz4")
	framed, err := c.CompressFrame(original)
	if err != nil {
		t.Fatal(err)
	}
	if framed[0] != compressByteUncompressed {
		t.Fatalf("expected uncompressed byte 0x00, got 0x%02x", framed[0])
	}
	// Decompress should handle the uncompressed framing.
	unframed, err := c.DecompressFrame(framed)
	if err != nil {
		t.Fatal(err)
	}
	if string(unframed) != string(original) {
		t.Fatalf("round-trip mismatch: got %q, want %q", unframed, original)
	}
}

func TestCompressorLZ4StubWhenNoCompression(t *testing.T) {
	// LZ4 mode with allow-compression=no sends stub framing.
	c := NewCompressor(CompressionLZ4, AllowCompressionNo)
	original := []byte("hello lz4 stub")
	framed, err := c.CompressFrame(original)
	if err != nil {
		t.Fatal(err)
	}
	if framed[0] != compressByteStub {
		t.Fatalf("expected stub byte 0x50, got 0x%02x", framed[0])
	}
}

func TestCompressorLZ4RejectsCompressedWhenNotAllowed(t *testing.T) {
	c := NewCompressor(CompressionLZ4, AllowCompressionNo)
	// Simulate receiving a compressed LZ4 packet.
	compressed := []byte{compressByteLZ4, 0x01, 0x02, 0x03}
	_, err := c.DecompressFrame(compressed)
	if err == nil {
		t.Fatal("expected error when receiving compressed packet with allow-compression=no")
	}
}

func TestCompressorLZ4AcceptsStub(t *testing.T) {
	c := NewCompressor(CompressionLZ4, AllowCompressionNo)
	// Receiving a stub-framed packet should be accepted.
	stubFramed := []byte{compressByteStub, 0x01, 0x02, 0x03}
	unframed, err := c.DecompressFrame(stubFramed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(unframed) != string([]byte{0x01, 0x02, 0x03}) {
		t.Fatalf("unexpected decompressed data: %v", unframed)
	}
}

func TestBuildCompressorWithCompression(t *testing.T) {
	cfg := ClientConfig{
		Compression: "stub-v2",
	}
	c := cfg.buildCompressor()
	if c == nil {
		t.Fatal("expected non-nil compressor")
	}
	if c.Mode() != CompressionStubV2 {
		t.Fatalf("expected CompressionStubV2, got %d", c.Mode())
	}
}

func TestBuildCompressorWithCompLZO(t *testing.T) {
	cfg := ClientConfig{
		CompLZO: CompLzoYes,
	}
	c := cfg.buildCompressor()
	if c == nil {
		t.Fatal("expected non-nil compressor for comp-lzo")
	}
	if c.Mode() != CompressionLZO {
		t.Fatalf("expected CompressionLZO, got %d", c.Mode())
	}
}

func TestBuildCompressorNone(t *testing.T) {
	cfg := ClientConfig{}
	c := cfg.buildCompressor()
	if c != nil {
		t.Fatal("expected nil compressor when no compression configured")
	}
}

func TestInstallScriptPeerInfoWithStubV2(t *testing.T) {
	info := InstallScriptPeerInfo(CipherAES128GCM, nil, "", "stub-v2", nil)
	if !contains(info, "IV_COMP_STUB=1") {
		t.Fatalf("expected IV_COMP_STUB=1 in peer-info: %q", info)
	}
	if !contains(info, "IV_COMP_STUBv2=1") {
		t.Fatalf("expected IV_COMP_STUBv2=1 in peer-info: %q", info)
	}
}

func TestInstallScriptPeerInfoWithStub(t *testing.T) {
	info := InstallScriptPeerInfo(CipherAES128GCM, nil, "", "stub", nil)
	if !contains(info, "IV_COMP_STUB=1") {
		t.Fatalf("expected IV_COMP_STUB=1 in peer-info: %q", info)
	}
	if contains(info, "IV_COMP_STUBv2") {
		t.Fatalf("did not expect IV_COMP_STUBv2 in peer-info: %q", info)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
