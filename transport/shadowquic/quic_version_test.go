package shadowquic

import (
	"testing"

	"github.com/metacubex/jls-quic-go"
)

func TestParseQUICVersions(t *testing.T) {
	versions, err := ParseQUICVersions([]string{
		"v1",
		"v2",
		"rfc9000",
		"rfc-9369",
		"v1",
	})
	if err != nil {
		t.Fatal(err)
	}

	want := []quic.Version{quic.Version1, quic.Version2}
	if !equalQUICVersions(versions, want) {
		t.Fatalf("versions = %v, want %v", versions, want)
	}
}

func TestParseQUICVersionsRejectsUnsupportedVersions(t *testing.T) {
	for _, version := range []string{"draft-29", "0xabcd0000", "v3"} {
		t.Run(version, func(t *testing.T) {
			if _, err := ParseQUICVersions([]string{version}); err == nil {
				t.Fatalf("ParseQUICVersions(%q) succeeded", version)
			}
		})
	}
}

func equalQUICVersions(a, b []quic.Version) bool {
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
