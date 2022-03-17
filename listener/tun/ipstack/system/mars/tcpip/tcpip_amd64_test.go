package tcpip

import (
	"crypto/rand"
	"testing"

	"golang.org/x/sys/cpu"
)

func Test_SumAVX2(t *testing.T) {
	if !cpu.X86.HasAVX2 {
		t.Skipf("AVX2 unavailable")
	}

	bytes := make([]byte, chunkSize)

	for size := 0; size <= chunkSize; size++ {
		for count := 0; count < chunkCount; count++ {
			_, err := rand.Reader.Read(bytes[:size])
			if err != nil {
				t.Skipf("Rand read failed: %v", err)
			}

			compat := SumCompat(bytes[:size])
			avx := SumAVX2(bytes[:size])

			if compat != avx {
				t.Errorf("Sum of length=%d mismatched", size)
			}
		}
	}
}

func Benchmark_SumAVX2(b *testing.B) {
	if !cpu.X86.HasAVX2 {
		b.Skipf("AVX2 unavailable")
	}

	bytes := make([]byte, chunkSize)

	_, err := rand.Reader.Read(bytes)
	if err != nil {
		b.Skipf("Rand read failed: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		SumAVX2(bytes)
	}
}
