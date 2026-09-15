package cidr

import (
	"bytes"
	"testing"
)

func FuzzReadIpCidrSet(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ReadIpCidrSet(bytes.NewReader(data))
	})
}
