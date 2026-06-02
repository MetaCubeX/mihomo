package openvpn

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestLzo1xSafe(t *testing.T) {
	data := make([]byte, 1024)
	rand.Read(data)
	compressed, err := lzo1xCompressSafe(data)
	if err != nil {
		t.Fatal(err)
	}
	decompressed, err := lzo1xDecompressSafe(compressed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decompressed) {
		t.Fatal("decompressed data is not equal to original")
	}
}
