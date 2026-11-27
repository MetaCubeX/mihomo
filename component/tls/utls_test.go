package tls

import (
	"testing"

	utls "github.com/metacubex/utls"
)

func TestVersionedChromeFingerprint(t *testing.T) {
	for name, want := range map[string]UClientHelloID{
		"chrome":    utls.HelloChrome_Auto,
		"chrome120": utls.HelloChrome_120,
		"chrome158": utls.HelloChrome_158,
	} {
		got, ok := GetFingerprint(name)
		if !ok || got != want {
			t.Errorf("GetFingerprint(%q) = %v, %t; want %v, true", name, got, ok, want)
		}
	}
}
