package orderedmap

// Adapted from https://github.com/dvyukov/go-fuzz-corpus/blob/c42c1b2/json/json.go

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func FuzzRoundTripYAML(f *testing.F) {
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
				if yaml.Unmarshal(data, v1) != nil {
					return
				}
				t.Log(data)
				t.Log(v1)

				yamlData, err := yaml.Marshal(v1)
				require.NoError(t, err)
				t.Log(string(yamlData))

				v2 := testCase.constructor()
				err = yaml.Unmarshal(yamlData, v2)
				if err != nil {
					t.Log(string(yamlData))
					t.Fatal(err)
				}

				if !assert.True(t, testCase.equalityAssertion(t, v1, v2), "failed with input data %q", string(data)) {
					// look at that what the standard lib does with regular map, to help with debugging

					var m1 map[string]any
					require.NoError(t, yaml.Unmarshal(data, &m1))

					mapJsonData, err := yaml.Marshal(m1)
					require.NoError(t, err)

					var m2 map[string]any
					require.NoError(t, yaml.Unmarshal(mapJsonData, &m2))

					t.Logf("initial data = %s", string(data))
					t.Logf("unmarshalled map = %v", m1)
					t.Logf("re-marshalled from map = %s", string(mapJsonData))
					t.Logf("re-marshalled from test obj = %s", string(yamlData))
					t.Logf("re-unmarshalled map = %s", m2)
				}
			})
		}
	})
}
