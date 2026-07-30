package route

import (
	"math"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMemoryLimit(t *testing.T) {
	original := debug.SetMemoryLimit(-1)
	t.Cleanup(func() {
		debug.SetMemoryLimit(original)
	})

	// no limit in effect
	debug.SetMemoryLimit(math.MaxInt64)
	assert.Equal(t, uint64(0), memoryLimit())

	// a limit is in effect
	debug.SetMemoryLimit(64 << 20)
	assert.Equal(t, uint64(64<<20), memoryLimit())

	// reading must not change the limit
	assert.Equal(t, uint64(64<<20), memoryLimit())
	assert.Equal(t, int64(64<<20), debug.SetMemoryLimit(-1))
}
