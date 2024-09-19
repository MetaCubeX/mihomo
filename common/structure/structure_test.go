package structure

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	decoder         = NewDecoder(Option{TagName: "test"})
	weakTypeDecoder = NewDecoder(Option{TagName: "test", WeaklyTypedInput: true})
)

type Baz struct {
	Foo int    `test:"foo"`
	Bar string `test:"bar"`
}

type BazSlice struct {
	Foo int      `test:"foo"`
	Bar []string `test:"bar"`
}

type BazOptional struct {
	Foo int    `test:"foo,omitempty"`
	Bar string `test:"bar,omitempty"`
}

func TestStructure_Basic(t *testing.T) {
	rawMap := map[string]any{
		"foo":   1,
		"bar":   "test",
		"extra": false,
	}

	goal := &Baz{
		Foo: 1,
		Bar: "test",
	}

	s := &Baz{}
	err := decoder.Decode(rawMap, s)
	assert.Nil(t, err)
	assert.Equal(t, goal, s)
}

func TestStructure_Slice(t *testing.T) {
	rawMap := map[string]any{
		"foo": 1,
		"bar": []string{"one", "two"},
	}

	goal := &BazSlice{
		Foo: 1,
		Bar: []string{"one", "two"},
	}

	s := &BazSlice{}
	err := decoder.Decode(rawMap, s)
	assert.Nil(t, err)
	assert.Equal(t, goal, s)
}

func TestStructure_Optional(t *testing.T) {
	rawMap := map[string]any{
		"foo": 1,
	}

	goal := &BazOptional{
		Foo: 1,
	}

	s := &BazOptional{}
	err := decoder.Decode(rawMap, s)
	assert.Nil(t, err)
	assert.Equal(t, goal, s)
}

func TestStructure_MissingKey(t *testing.T) {
	rawMap := map[string]any{
		"foo": 1,
	}

	s := &Baz{}
	err := decoder.Decode(rawMap, s)
	assert.NotNilf(t, err, "should throw error: %#v", s)
}

func TestStructure_ParamError(t *testing.T) {
	rawMap := map[string]any{}
	s := Baz{}
	err := decoder.Decode(rawMap, s)
	assert.NotNilf(t, err, "should throw error: %#v", s)
}

func TestStructure_SliceTypeError(t *testing.T) {
	rawMap := map[string]any{
		"foo": 1,
		"bar": []int{1, 2},
	}

	s := &BazSlice{}
	err := decoder.Decode(rawMap, s)
	assert.NotNilf(t, err, "should throw error: %#v", s)
}

func TestStructure_WeakType(t *testing.T) {
	rawMap := map[string]any{
		"foo": "1",
		"bar": []int{1},
	}

	goal := &BazSlice{
		Foo: 1,
		Bar: []string{"1"},
	}

	s := &BazSlice{}
	err := weakTypeDecoder.Decode(rawMap, s)
	assert.Nil(t, err)
	assert.Equal(t, goal, s)
}

func TestStructure_Nest(t *testing.T) {
	rawMap := map[string]any{
		"foo": 1,
	}

	goal := BazOptional{
		Foo: 1,
	}

	s := &struct {
		BazOptional
	}{}
	err := decoder.Decode(rawMap, s)
	assert.Nil(t, err)
	assert.Equal(t, s.BazOptional, goal)
}

func TestStructure_SliceNilValue(t *testing.T) {
	rawMap := map[string]any{
		"foo": 1,
		"bar": []any{"bar", nil},
	}

	goal := &BazSlice{
		Foo: 1,
		Bar: []string{"bar", ""},
	}

	s := &BazSlice{}
	err := weakTypeDecoder.Decode(rawMap, s)
	assert.Nil(t, err)
	assert.Equal(t, goal.Bar, s.Bar)

	s = &BazSlice{}
	err = decoder.Decode(rawMap, s)
	assert.NotNil(t, err)
}

func TestStructure_SliceNilValueComplex(t *testing.T) {
	rawMap := map[string]any{
		"bar": []any{map[string]any{"bar": "foo"}, nil},
	}

	s := &struct {
		Bar []map[string]any `test:"bar"`
	}{}

	err := decoder.Decode(rawMap, s)
	assert.Nil(t, err)
	assert.Nil(t, s.Bar[1])

	ss := &struct {
		Bar []Baz `test:"bar"`
	}{}

	err = decoder.Decode(rawMap, ss)
	assert.NotNil(t, err)
}

func TestStructure_SliceCap(t *testing.T) {
	rawMap := map[string]any{
		"foo": []string{},
	}

	s := &struct {
		Foo []string `test:"foo,omitempty"`
		Bar []string `test:"bar,omitempty"`
	}{}

	err := decoder.Decode(rawMap, s)
	assert.Nil(t, err)
	assert.NotNil(t, s.Foo) // structure's Decode will ensure value not nil when input has value even it was set an empty array
	assert.Nil(t, s.Bar)
}

func TestStructure_Base64(t *testing.T) {
	rawMap := map[string]any{
		"foo": "AQID",
	}

	s := &struct {
		Foo []byte `test:"foo"`
	}{}

	err := decoder.Decode(rawMap, s)
	assert.Nil(t, err)
	assert.Equal(t, []byte{1, 2, 3}, s.Foo)
}

func TestStructure_Pointer(t *testing.T) {
	rawMap := map[string]any{
		"foo": "foo",
	}

	s := &struct {
		Foo *string `test:"foo,omitempty"`
		Bar *string `test:"bar,omitempty"`
	}{}

	err := decoder.Decode(rawMap, s)
	assert.Nil(t, err)
	assert.NotNil(t, s.Foo)
	assert.Equal(t, "foo", *s.Foo)
	assert.Nil(t, s.Bar)
}

type num struct {
	a int
}

func (n *num) UnmarshalText(text []byte) (err error) {
	n.a, err = strconv.Atoi(string(text))
	return
}

func TestStructure_TextUnmarshaller(t *testing.T) {
	rawMap := map[string]any{
		"num":   "255",
		"num_p": "127",
	}

	s := &struct {
		Num  num  `test:"num"`
		NumP *num `test:"num_p"`
	}{}

	err := decoder.Decode(rawMap, s)
	assert.Nil(t, err)
	assert.Equal(t, 255, s.Num.a)
	assert.NotNil(t, s.NumP)
	assert.Equal(t, s.NumP.a, 127)

	// test WeaklyTypedInput
	rawMap["num"] = 256
	err = decoder.Decode(rawMap, s)
	assert.NotNilf(t, err, "should throw error: %#v", s)
	err = weakTypeDecoder.Decode(rawMap, s)
	assert.Nil(t, err)
	assert.Equal(t, 256, s.Num.a)

	// test invalid input
	rawMap["num_p"] = "abc"
	err = decoder.Decode(rawMap, s)
	assert.NotNilf(t, err, "should throw error: %#v", s)
}
