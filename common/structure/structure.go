package structure

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// Option is the configuration that is used to create a new decoder
type Option struct {
	TagName          string
	WeaklyTypedInput bool
}

// Decoder is the core of structure
type Decoder struct {
	option *Option
}

// NewDecoder return a Decoder by Option
func NewDecoder(option Option) *Decoder {
	if option.TagName == "" {
		option.TagName = "structure"
	}
	return &Decoder{option: &option}
}

// Decode transform a map[string]interface{} to a struct
func (d *Decoder) Decode(src map[string]interface{}, dst interface{}) error {
	if reflect.TypeOf(dst).Kind() != reflect.Ptr {
		return fmt.Errorf("Decode must recive a ptr struct")
	}
	t := reflect.TypeOf(dst).Elem()
	v := reflect.ValueOf(dst).Elem()
	for idx := 0; idx < v.NumField(); idx++ {
		field := t.Field(idx)

		tag := field.Tag.Get(d.option.TagName)
		str := strings.SplitN(tag, ",", 2)
		key := str[0]
		omitempty := false
		if len(str) > 1 {
			omitempty = str[1] == "omitempty"
		}

		value, ok := src[key]
		if !ok {
			if omitempty {
				continue
			}
			return fmt.Errorf("key %s missing", key)
		}

		err := d.decode(key, value, v.Field(idx))
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *Decoder) decode(name string, data interface{}, val reflect.Value) error {
	switch val.Kind() {
	case reflect.Int:
		return d.decodeInt(name, data, val)
	case reflect.String:
		return d.decodeString(name, data, val)
	case reflect.Bool:
		return d.decodeBool(name, data, val)
	case reflect.Slice:
		return d.decodeSlice(name, data, val)
	default:
		return fmt.Errorf("type %s not support", val.Kind().String())
	}
}

func (d *Decoder) decodeInt(name string, data interface{}, val reflect.Value) (err error) {
	dataVal := reflect.ValueOf(data)
	kind := dataVal.Kind()
	switch {
	case kind == reflect.Int:
		val.SetInt(dataVal.Int())
	case kind == reflect.String && d.option.WeaklyTypedInput:
		var i int64
		i, err = strconv.ParseInt(dataVal.String(), 0, val.Type().Bits())
		if err == nil {
			val.SetInt(i)
		} else {
			err = fmt.Errorf("cannot parse '%s' as int: %s", name, err)
		}
	default:
		err = fmt.Errorf(
			"'%s' expected type '%s', got unconvertible type '%s'",
			name, val.Type(), dataVal.Type(),
		)
	}
	return err
}

func (d *Decoder) decodeString(name string, data interface{}, val reflect.Value) (err error) {
	dataVal := reflect.ValueOf(data)
	kind := dataVal.Kind()
	switch {
	case kind == reflect.String:
		val.SetString(dataVal.String())
	case kind == reflect.Int && d.option.WeaklyTypedInput:
		val.SetString(strconv.FormatInt(dataVal.Int(), 10))
	default:
		err = fmt.Errorf(
			"'%s' expected type'%s', got unconvertible type '%s'",
			name, val.Type(), dataVal.Type(),
		)
	}
	return err
}

func (d *Decoder) decodeBool(name string, data interface{}, val reflect.Value) (err error) {
	dataVal := reflect.ValueOf(data)
	kind := dataVal.Kind()
	switch {
	case kind == reflect.Bool:
		val.SetBool(dataVal.Bool())
	case kind == reflect.Int && d.option.WeaklyTypedInput:
		val.SetBool(dataVal.Int() != 0)
	default:
		err = fmt.Errorf(
			"'%s' expected type'%s', got unconvertible type '%s'",
			name, val.Type(), dataVal.Type(),
		)
	}
	return err
}

func (d *Decoder) decodeSlice(name string, data interface{}, val reflect.Value) error {
	dataVal := reflect.Indirect(reflect.ValueOf(data))
	valType := val.Type()
	valElemType := valType.Elem()

	if dataVal.Kind() != reflect.Slice {
		return fmt.Errorf("'%s' is not a slice", name)
	}

	valSlice := val
	for i := 0; i < dataVal.Len(); i++ {
		currentData := dataVal.Index(i).Interface()
		for valSlice.Len() <= i {
			valSlice = reflect.Append(valSlice, reflect.Zero(valElemType))
		}
		currentField := valSlice.Index(i)

		fieldName := fmt.Sprintf("%s[%d]", name, i)
		if err := d.decode(fieldName, currentData, currentField); err != nil {
			return err
		}
	}

	val.Set(valSlice)
	return nil
}
