package utils

// modify from https://github.com/go-yaml/yaml/issues/698#issuecomment-1482026841

import (
	"errors"
	"gopkg.in/yaml.v3"
)

type StringMapSlice[V any] []StringMapSliceItem[V]

type StringMapSliceItem[V any] struct {
	Key   string
	Value V
}

func (s *StringMapSlice[V]) UnmarshalYAML(value *yaml.Node) error {
	for i := 0; i < len(value.Content); i += 2 {
		if i+1 >= len(value.Content) {
			return errors.New("not a dict")
		}
		item := StringMapSliceItem[V]{}
		item.Key = value.Content[i].Value
		if err := value.Content[i+1].Decode(&item.Value); err != nil {
			return err
		}

		*s = append(*s, item)
	}

	return nil
}

func (s *StringMapSlice[V]) Add(key string, value V) {
	*s = append(*s, StringMapSliceItem[V]{Key: key, Value: value})
}

func (i *StringMapSliceItem[V]) Extract() (key string, value V) {
	return i.Key, i.Value
}
