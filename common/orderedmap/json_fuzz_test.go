package orderedmap

// Adapted from https://github.com/dvyukov/go-fuzz-corpus/blob/c42c1b2/json/json.go

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func FuzzRoundTripJSON(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, testCase := range []struct {
			name        string
			constructor func() any
			// should be a function that asserts that 2 objects of the type returned by constructor are equal
			equalityAssertion func(*testing.T, any, any) bool
		}{
			{
				name:              "with a string -> string map",
				constructor:       func() any { return &OrderedMap[string, string]{} },
				equalityAssertion: assertOrderedMapsEqual[string, string],
			},
			{
				name:              "with a string -> int map",
				constructor:       func() any { return &OrderedMap[string, int]{} },
				equalityAssertion: assertOrderedMapsEqual[string, int],
			},
			{
				name:              "with a string -> any map",
				constructor:       func() any { return &OrderedMap[string, any]{} },
				equalityAssertion: assertOrderedMapsEqual[string, any],
			},
			{
				name:              "with a struct with map fields",
				constructor:       func() any { return new(testFuzzStruct) },
				equalityAssertion: assertTestFuzzStructEqual,
			},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				v1 := testCase.constructor()
				if json.Unmarshal(data, v1) != nil {
					return
				}

				jsonData, err := json.Marshal(v1)
				require.NoError(t, err)

				v2 := testCase.constructor()
				require.NoError(t, json.Unmarshal(jsonData, v2))

				if !assert.True(t, testCase.equalityAssertion(t, v1, v2), "failed with input data %q", string(data)) {
					// look at that what the standard lib does with regular map, to help with debugging

					var m1 map[string]any
					require.NoError(t, json.Unmarshal(data, &m1))

					mapJsonData, err := json.Marshal(m1)
					require.NoError(t, err)

					var m2 map[string]any
					require.NoError(t, json.Unmarshal(mapJsonData, &m2))

					t.Logf("initial data = %s", string(data))
					t.Logf("unmarshalled map = %v", m1)
					t.Logf("re-marshalled from map = %s", string(mapJsonData))
					t.Logf("re-marshalled from test obj = %s", string(jsonData))
					t.Logf("re-unmarshalled map = %s", m2)
				}
			})
		}
	})
}

// only works for fairly basic maps, that's why it's just in this file
func assertOrderedMapsEqual[K comparable, V any](t *testing.T, v1, v2 any) bool {
	om1, ok1 := v1.(*OrderedMap[K, V])
	om2, ok2 := v2.(*OrderedMap[K, V])

	if !assert.True(t, ok1, "v1 not an orderedmap") ||
		!assert.True(t, ok2, "v2 not an orderedmap") {
		return false
	}

	success := assert.Equal(t, om1.Len(), om2.Len(), "om1 and om2 have different lengths: %d vs %d", om1.Len(), om2.Len())

	for i, pair1, pair2 := 0, om1.Oldest(), om2.Oldest(); pair1 != nil && pair2 != nil; i, pair1, pair2 = i+1, pair1.Next(), pair2.Next() {
		success = assert.Equal(t, pair1.Key, pair2.Key, "different keys at position %d: %v vs %v", i, pair1.Key, pair2.Key) && success
		success = assert.Equal(t, pair1.Value, pair2.Value, "different values at position %d: %v vs %v", i, pair1.Value, pair2.Value) && success
	}

	return success
}

type testFuzzStruct struct {
	M1 *OrderedMap[int, any]
	M2 *OrderedMap[int, string]
	M3 *OrderedMap[string, string]
}

func assertTestFuzzStructEqual(t *testing.T, v1, v2 any) bool {
	s1, ok := v1.(*testFuzzStruct)
	s2, ok := v2.(*testFuzzStruct)

	if !assert.True(t, ok, "v1 not an testFuzzStruct") ||
		!assert.True(t, ok, "v2 not an testFuzzStruct") {
		return false
	}

	success := assertOrderedMapsEqual[int, any](t, s1.M1, s2.M1)
	success = assertOrderedMapsEqual[int, string](t, s1.M2, s2.M2) && success
	success = assertOrderedMapsEqual[string, string](t, s1.M3, s2.M3) && success

	return success
}
