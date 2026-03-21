package orderedmap

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// to test marshalling TextMarshalers and unmarshalling TextUnmarshalers
type marshallable int

func (m marshallable) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf("#%d#", m)), nil
}

func (m *marshallable) UnmarshalText(text []byte) error {
	if len(text) < 3 {
		return errors.New("too short")
	}
	if text[0] != '#' || text[len(text)-1] != '#' {
		return errors.New("missing prefix or suffix")
	}

	value, err := strconv.Atoi(string(text[1 : len(text)-1]))
	if err != nil {
		return err
	}

	*m = marshallable(value)
	return nil
}

func TestMarshalJSON(t *testing.T) {
	t.Run("int key", func(t *testing.T) {
		om := New[int, any]()
		om.Set(1, "bar")
		om.Set(7, "baz")
		om.Set(2, 28)
		om.Set(3, 100)
		om.Set(4, "baz")
		om.Set(5, "28")
		om.Set(6, "100")
		om.Set(8, "baz")
		om.Set(8, "baz")
		om.Set(9, "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque auctor augue accumsan mi maximus, quis viverra massa pretium. Phasellus imperdiet sapien a interdum sollicitudin. Duis at commodo lectus, a lacinia sem.")

		b, err := json.Marshal(om)
		assert.NoError(t, err)
		assert.Equal(t, `{"1":"bar","7":"baz","2":28,"3":100,"4":"baz","5":"28","6":"100","8":"baz","9":"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque auctor augue accumsan mi maximus, quis viverra massa pretium. Phasellus imperdiet sapien a interdum sollicitudin. Duis at commodo lectus, a lacinia sem."}`, string(b))
	})

	t.Run("string key", func(t *testing.T) {
		om := New[string, any]()
		om.Set("test", "bar")
		om.Set("abc", true)

		b, err := json.Marshal(om)
		assert.NoError(t, err)
		assert.Equal(t, `{"test":"bar","abc":true}`, string(b))
	})

	t.Run("typed string key", func(t *testing.T) {
		type myString string
		om := New[myString, any]()
		om.Set("test", "bar")
		om.Set("abc", true)

		b, err := json.Marshal(om)
		assert.NoError(t, err)
		assert.Equal(t, `{"test":"bar","abc":true}`, string(b))
	})

	t.Run("typed int key", func(t *testing.T) {
		type myInt uint32
		om := New[myInt, any]()
		om.Set(1, "bar")
		om.Set(7, "baz")
		om.Set(2, 28)
		om.Set(3, 100)
		om.Set(4, "baz")

		b, err := json.Marshal(om)
		assert.NoError(t, err)
		assert.Equal(t, `{"1":"bar","7":"baz","2":28,"3":100,"4":"baz"}`, string(b))
	})

	t.Run("TextMarshaller key", func(t *testing.T) {
		om := New[marshallable, any]()
		om.Set(marshallable(1), "bar")
		om.Set(marshallable(28), true)

		b, err := json.Marshal(om)
		assert.NoError(t, err)
		assert.Equal(t, `{"#1#":"bar","#28#":true}`, string(b))
	})

	t.Run("empty map", func(t *testing.T) {
		om := New[string, any]()

		b, err := json.Marshal(om)
		assert.NoError(t, err)
		assert.Equal(t, `{}`, string(b))
	})
}

func TestUnmarshallJSON(t *testing.T) {
	t.Run("int key", func(t *testing.T) {
		data := `{"1":"bar","7":"baz","2":28,"3":100,"4":"baz","5":"28","6":"100","8":"baz"}`

		om := New[int, any]()
		require.NoError(t, json.Unmarshal([]byte(data), &om))

		assertOrderedPairsEqual(t, om,
			[]int{1, 7, 2, 3, 4, 5, 6, 8},
			[]any{"bar", "baz", float64(28), float64(100), "baz", "28", "100", "baz"})
	})

	t.Run("string key", func(t *testing.T) {
		data := `{"test":"bar","abc":true}`

		om := New[string, any]()
		require.NoError(t, json.Unmarshal([]byte(data), &om))

		assertOrderedPairsEqual(t, om,
			[]string{"test", "abc"},
			[]any{"bar", true})
	})

	t.Run("typed string key", func(t *testing.T) {
		data := `{"test":"bar","abc":true}`

		type myString string
		om := New[myString, any]()
		require.NoError(t, json.Unmarshal([]byte(data), &om))

		assertOrderedPairsEqual(t, om,
			[]myString{"test", "abc"},
			[]any{"bar", true})
	})

	t.Run("typed int key", func(t *testing.T) {
		data := `{"1":"bar","7":"baz","2":28,"3":100,"4":"baz","5":"28","6":"100","8":"baz"}`

		type myInt uint32
		om := New[myInt, any]()
		require.NoError(t, json.Unmarshal([]byte(data), &om))

		assertOrderedPairsEqual(t, om,
			[]myInt{1, 7, 2, 3, 4, 5, 6, 8},
			[]any{"bar", "baz", float64(28), float64(100), "baz", "28", "100", "baz"})
	})

	t.Run("TextUnmarshaler key", func(t *testing.T) {
		data := `{"#1#":"bar","#28#":true}`

		om := New[marshallable, any]()
		require.NoError(t, json.Unmarshal([]byte(data), &om))

		assertOrderedPairsEqual(t, om,
			[]marshallable{1, 28},
			[]any{"bar", true})
	})

	t.Run("when fed with an input that's not an object", func(t *testing.T) {
		for _, data := range []string{"true", `["foo"]`, "42", `"foo"`} {
			om := New[int, any]()
			require.Error(t, json.Unmarshal([]byte(data), &om))
		}
	})

	t.Run("empty map", func(t *testing.T) {
		data := `{}`

		om := New[int, any]()
		require.NoError(t, json.Unmarshal([]byte(data), &om))

		assertLenEqual(t, om, 0)
	})
}

// const specialCharacters = "\\\\/\"\b\f\n\r\t\x00\uffff\ufffd世界\u007f\u00ff\U0010FFFF"
const specialCharacters = "\uffff\ufffd世界\u007f\u00ff\U0010FFFF"

func TestJSONSpecialCharacters(t *testing.T) {
	baselineMap := map[string]any{specialCharacters: specialCharacters}
	baselineData, err := json.Marshal(baselineMap)
	require.NoError(t, err) // baseline proves this key is supported by official json library
	t.Logf("specialCharacters: %#v as []rune:%v", specialCharacters, []rune(specialCharacters))
	t.Logf("baseline json data: %s", baselineData)

	t.Run("marshal special characters", func(t *testing.T) {
		om := New[string, any]()
		om.Set(specialCharacters, specialCharacters)
		b, err := json.Marshal(om)
		require.NoError(t, err)
		require.Equal(t, baselineData, b)

		type myString string
		om2 := New[myString, myString]()
		om2.Set(specialCharacters, specialCharacters)
		b, err = json.Marshal(om2)
		require.NoError(t, err)
		require.Equal(t, baselineData, b)
	})

	t.Run("unmarshall special characters", func(t *testing.T) {
		om := New[string, any]()
		require.NoError(t, json.Unmarshal(baselineData, &om))
		assertOrderedPairsEqual(t, om,
			[]string{specialCharacters},
			[]any{specialCharacters})

		type myString string
		om2 := New[myString, myString]()
		require.NoError(t, json.Unmarshal(baselineData, &om2))
		assertOrderedPairsEqual(t, om2,
			[]myString{specialCharacters},
			[]myString{specialCharacters})
	})
}

// to test structs that have nested map fields
type nestedMaps struct {
	X int                                                               `json:"x" yaml:"x"`
	M *OrderedMap[string, []*OrderedMap[int, *OrderedMap[string, any]]] `json:"m" yaml:"m"`
}

func TestJSONRoundTrip(t *testing.T) {
	for _, testCase := range []struct {
		name            string
		input           string
		targetFactory   func() any
		isPrettyPrinted bool
	}{
		{
			name: "",
			input: `{
    "x": 28,
    "m": {
        "foo": [
            {
                "12": {
                    "i": 12,
                    "b": true,
                    "n": null,
                    "m": {
                        "a": "b",
                        "c": 28
                    }
                },
                "28": {
                    "a": false,
                    "b": [
                        1,
                        2,
                        3
                    ]
                }
            },
            {
                "3": {
                    "c": null,
                    "d": 87
                },
                "4": {
                    "e": true
                },
                "5": {
                    "f": 4,
                    "g": 5,
                    "h": 6
                }
            }
        ],
        "bar": [
            {
                "5": {
                    "foo": "bar"
                }
            }
        ]
    }
}`,
			targetFactory:   func() any { return &nestedMaps{} },
			isPrettyPrinted: true,
		},
		{
			name:          "with UTF-8 special chars in key",
			input:         `{"�":0}`,
			targetFactory: func() any { return &OrderedMap[string, int]{} },
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			target := testCase.targetFactory()

			require.NoError(t, json.Unmarshal([]byte(testCase.input), target))

			var (
				out []byte
				err error
			)
			if testCase.isPrettyPrinted {
				out, err = json.MarshalIndent(target, "", "    ")
			} else {
				out, err = json.Marshal(target)
			}

			if assert.NoError(t, err) {
				assert.Equal(t, strings.TrimSpace(testCase.input), string(out))
			}
		})
	}
}

func BenchmarkMarshalJSON(b *testing.B) {
	om := New[int, any]()
	om.Set(1, "bar")
	om.Set(7, "baz")
	om.Set(2, 28)
	om.Set(3, 100)
	om.Set(4, "baz")
	om.Set(5, "28")
	om.Set(6, "100")
	om.Set(8, "baz")
	om.Set(8, "baz")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(om)
	}
}
