package outbound

import (
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRealityOptionsParseXrayAliasesAndSpider(t *testing.T) {
	publicKey := make([]byte, 32)
	publicKey[0] = 1
	verifyKey := make([]byte, 1952)
	verifyKey[0] = 2

	config, err := (RealityOptions{
		PublicKey:     "invalid-but-overridden",
		Password:      base64.RawURLEncoding.EncodeToString(publicKey),
		ShortID:       "0123456789abcdef",
		Mldsa65Verify: base64.RawURLEncoding.EncodeToString(verifyKey),
		SpiderX:       "/start?keep=yes&p=10-20&c=2&t=3-4&i=5&r=6-7",
		Show:          true,
	}).Parse()
	if err != nil {
		t.Fatal(err)
	}
	if got := config.PublicKey.Bytes(); !equalBytes(got, publicKey) {
		t.Fatalf("public key = %v, want %v", got, publicKey)
	}
	if got := config.Mldsa65Verify; !equalBytes(got, verifyKey) {
		t.Fatalf("ML-DSA-65 verify key length = %d, want %d", len(got), len(verifyKey))
	}
	if got, want := config.SpiderX, "/start?keep=yes"; got != want {
		t.Fatalf("SpiderX = %q, want %q", got, want)
	}
	if got, want := config.SpiderY, [10]int64{10, 20, 2, 2, 3, 4, 5, 5, 6, 7}; got != want {
		t.Fatalf("SpiderY = %v, want %v", got, want)
	}
	if !config.Show {
		t.Fatal("Show = false, want true")
	}
}

func TestRealityOptionsParseDefaultsSpider(t *testing.T) {
	config, err := (RealityOptions{
		PublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}).Parse()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := config.SpiderX, "/"; got != want {
		t.Fatalf("SpiderX = %q, want %q", got, want)
	}
}

func TestRealityOptionsParseRejectsInvalidMldsa65Verify(t *testing.T) {
	_, err := (RealityOptions{
		PublicKey:     base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		Mldsa65Verify: base64.RawURLEncoding.EncodeToString(make([]byte, 1951)),
	}).Parse()
	if err == nil {
		t.Fatal("Parse() error = nil")
	}
}

func TestRealityOptionsParseOpensMasterKeyLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reality.keys")
	config, err := (RealityOptions{
		PublicKey:    base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		MasterKeyLog: path,
	}).Parse()
	if err != nil {
		t.Fatal(err)
	}
	if config.KeyLogWriter == nil {
		t.Fatal("KeyLogWriter = nil")
	}
	if _, err := io.WriteString(config.KeyLogWriter, "CLIENT_RANDOM test\n"); err != nil {
		t.Fatal(err)
	}
	if closer, ok := config.KeyLogWriter.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			t.Fatal(err)
		}
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(contents), "CLIENT_RANDOM test\n"; got != want {
		t.Fatalf("key log = %q, want %q", got, want)
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
