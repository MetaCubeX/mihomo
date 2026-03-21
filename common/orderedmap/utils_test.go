package orderedmap

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// assertOrderedPairsEqual asserts that the map contains the given keys and values
// from oldest to newest.
func assertOrderedPairsEqual[K comparable, V any](
	t *testing.T, orderedMap *OrderedMap[K, V], expectedKeys []K, expectedValues []V,
) {
	t.Helper()

	assertOrderedPairsEqualFromNewest(t, orderedMap, expectedKeys, expectedValues)
	assertOrderedPairsEqualFromOldest(t, orderedMap, expectedKeys, expectedValues)
}

func assertOrderedPairsEqualFromNewest[K comparable, V any](
	t *testing.T, orderedMap *OrderedMap[K, V], expectedKeys []K, expectedValues []V,
) {
	t.Helper()

	if assert.Equal(t, len(expectedKeys), len(expectedValues)) && assert.Equal(t, len(expectedKeys), orderedMap.Len()) {
		i := orderedMap.Len() - 1
		for pair := orderedMap.Newest(); pair != nil; pair = pair.Prev() {
			assert.Equal(t, expectedKeys[i], pair.Key, "from newest index=%d on key", i)
			assert.Equal(t, expectedValues[i], pair.Value, "from newest index=%d on value", i)
			i--
		}
	}
}

func assertOrderedPairsEqualFromOldest[K comparable, V any](
	t *testing.T, orderedMap *OrderedMap[K, V], expectedKeys []K, expectedValues []V,
) {
	t.Helper()

	if assert.Equal(t, len(expectedKeys), len(expectedValues)) && assert.Equal(t, len(expectedKeys), orderedMap.Len()) {
		i := 0
		for pair := orderedMap.Oldest(); pair != nil; pair = pair.Next() {
			assert.Equal(t, expectedKeys[i], pair.Key, "from oldest index=%d on key", i)
			assert.Equal(t, expectedValues[i], pair.Value, "from oldest index=%d on value", i)
			i++
		}
	}
}

func assertLenEqual[K comparable, V any](t *testing.T, orderedMap *OrderedMap[K, V], expectedLen int) {
	t.Helper()

	assert.Equal(t, expectedLen, orderedMap.Len())

	// also check the list length, for good measure
	assert.Equal(t, expectedLen, orderedMap.list.Len())
}

func randomHexString(t *testing.T, length int) string {
	t.Helper()

	b := length / 2 //nolint:gomnd
	randBytes := make([]byte, b)

	if n, err := rand.Read(randBytes); err != nil || n != b {
		if err == nil {
			err = fmt.Errorf("only got %v random bytes, expected %v", n, b)
		}
		t.Fatal(err)
	}

	return hex.EncodeToString(randBytes)
}
