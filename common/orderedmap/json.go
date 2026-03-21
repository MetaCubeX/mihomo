package orderedmap

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

var (
	_ json.Marshaler   = &OrderedMap[int, any]{}
	_ json.Unmarshaler = &OrderedMap[int, any]{}
)

// MarshalJSON implements the json.Marshaler interface.
func (om *OrderedMap[K, V]) MarshalJSON() ([]byte, error) { //nolint:funlen
	if om == nil || om.list == nil {
		return []byte("null"), nil
	}

	var buf bytes.Buffer
	buf.WriteByte('{')
	enc := json.NewEncoder(&buf)
	for pair, firstIteration := om.Oldest(), true; pair != nil; pair = pair.Next() {
		if firstIteration {
			firstIteration = false
		} else {
			buf.WriteByte(',')
		}

		switch key := any(pair.Key).(type) {
		case string, encoding.TextMarshaler:
			if err := enc.Encode(pair.Key); err != nil {
				return nil, err
			}
		case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
			buf.WriteByte('"')
			buf.WriteString(fmt.Sprint(key))
			buf.WriteByte('"')
		default:
			// this switch takes care of wrapper types around primitive types, such as
			// type myType string
			switch keyValue := reflect.ValueOf(key); keyValue.Type().Kind() {
			case reflect.String:
				if err := enc.Encode(pair.Key); err != nil {
					return nil, err
				}
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
				reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				buf.WriteByte('"')
				buf.WriteString(fmt.Sprint(key))
				buf.WriteByte('"')
			default:
				return nil, fmt.Errorf("unsupported key type: %T", key)
			}
		}

		buf.WriteByte(':')
		if err := enc.Encode(pair.Value); err != nil {
			return nil, err
		}
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (om *OrderedMap[K, V]) UnmarshalJSON(data []byte) error {
	if om.list == nil {
		om.initialize(0)
	}

	d := json.NewDecoder(bytes.NewReader(data))
	tok, err := d.Token()
	if err != nil {
		return err
	}
	if tok != json.Delim('{') {
		return errors.New("expect JSON object open with '{'")
	}

	for d.More() {
		// key
		tok, err = d.Token()
		if err != nil {
			return err
		}

		keyStr, ok := tok.(string)
		if !ok {
			return fmt.Errorf("key must be a string, got %T\n", tok)
		}

		var key K
		switch typedKey := any(&key).(type) {
		case *string:
			*typedKey = keyStr
		case encoding.TextUnmarshaler:
			err = typedKey.UnmarshalText([]byte(keyStr))
		case *int, *int8, *int16, *int32, *int64, *uint, *uint8, *uint16, *uint32, *uint64:
			err = json.Unmarshal([]byte(keyStr), typedKey)
		default:
			// this switch takes care of wrapper types around primitive types, such as
			// type myType string
			switch reflect.TypeOf(key).Kind() {
			case reflect.String:
				convertedKeyData := reflect.ValueOf(keyStr).Convert(reflect.TypeOf(key))
				reflect.ValueOf(&key).Elem().Set(convertedKeyData)
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
				reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				err = json.Unmarshal([]byte(keyStr), &key)
			default:
				err = fmt.Errorf("unsupported key type: %T", key)
			}
		}
		if err != nil {
			return err
		}

		// value
		value, _ := om.Get(key)
		err = d.Decode(&value)
		if err != nil {
			return err
		}
		om.Set(key, value)
	}

	tok, err = d.Token()
	if err != nil {
		return err
	}
	if tok != json.Delim('}') {
		return errors.New("expect JSON object close with '}'")
	}
	return nil
}
