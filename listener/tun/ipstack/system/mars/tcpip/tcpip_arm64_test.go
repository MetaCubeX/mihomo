package tcpip

import (
	"crypto/rand"
	"testing"

	"golang.org/x/sys/cpu"
)

func Test_SumNeon(t *testing.T) {
	if !cpu.ARM64.HasASIMD {
		t.Skipf("Neon unavailable")
	}

	bytes := make([]byte, chunkSize)

	for size := 0; size <= chunkSize; size++ {
		for count := 0; count < chunkCount; count++ {
			_, err := rand.Reader.Read(bytes[:size])
			if err != nil {
				t.Skipf("Rand read failed: %v", err)
			}

			compat := SumCompat(bytes[:size])
			neon := SumNeon(bytes[:size])

			if compat != neon {
				t.Errorf("Sum of length=%d mismatched", size)
			}
		}
	}
}

func Benchmark_SumNeon(b *testing.B) {
	if !cpu.ARM64.HasASIMD {
		b.Skipf("Neon unavailable")
	}

	bytes := make([]byte, chunkSize)

	_, err := rand.Reader.Read(bytes)
	if err != nil {
		b.Skipf("Rand read failed: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		SumNeon(bytes)
	}
}
