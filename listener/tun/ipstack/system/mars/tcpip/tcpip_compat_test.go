package tcpip

import (
	"crypto/rand"
	"testing"
)

const (
	chunkSize  = 9000
	chunkCount = 10
)

func Benchmark_SumCompat(b *testing.B) {
	bytes := make([]byte, chunkSize)

	_, err := rand.Reader.Read(bytes)
	if err != nil {
		b.Skipf("Rand read failed: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		SumCompat(bytes)
	}
}
