package sniffer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBitmap(t *testing.T) {
	t.Run("zero value", func(t *testing.T) {
		var coverage bitmap
		assert.Equal(t, 0, coverage.firstUnset(0, 128))
		assert.Equal(t, 0, coverage.firstUnset(0, 0))
	})

	t.Run("single word", func(t *testing.T) {
		var coverage bitmap
		coverage.setRange(1, 5)
		assert.Equal(t, 0, coverage.firstUnset(0, 5))
		assert.Equal(t, 5, coverage.firstUnset(1, 5))
		assert.Equal(t, 5, coverage.firstUnset(1, 6))
	})

	t.Run("cross word", func(t *testing.T) {
		var coverage bitmap
		coverage.setRange(1, 130)
		assert.Equal(t, 130, coverage.firstUnset(1, 130))
		assert.Equal(t, 130, coverage.firstUnset(1, 131))
	})

	t.Run("one bit gap", func(t *testing.T) {
		var coverage bitmap
		coverage.setRange(0, 64)
		coverage.setRange(65, 130)
		assert.Equal(t, 64, coverage.firstUnset(0, 130))
	})

	t.Run("overlap survives growth", func(t *testing.T) {
		var coverage bitmap
		coverage.setRange(0, 10)
		coverage.setRange(64, 70)
		coverage.setRange(8, 65)
		assert.Equal(t, 70, coverage.firstUnset(0, 71))
	})

	t.Run("invalid range", func(t *testing.T) {
		var coverage bitmap
		assert.Panics(t, func() { coverage.setRange(-1, 0) })
		assert.Panics(t, func() { coverage.setRange(1, 0) })
		assert.Panics(t, func() { coverage.firstUnset(-1, 0) })
		assert.Panics(t, func() { coverage.firstUnset(1, 0) })
	})
}
