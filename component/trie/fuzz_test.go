package trie

import (
	"bytes"
	"testing"
)

func FuzzReadDomainSetBin(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ReadDomainSetBin(bytes.NewReader(data))
	})
}
