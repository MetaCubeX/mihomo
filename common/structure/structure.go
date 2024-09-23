package structure

// references: https://github.com/mitchellh/mapstructure

import (
	"encoding"
	"encoding/base64"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// Option is the configuration that is used to create a new decoder
type Option struct {
	TagName          string
	WeaklyTypedInput bool
	KeyReplacer      *strings.Replacer
}

var DefaultKeyReplacer = strings.NewReplacer("_", "-")

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

// Decode transform a map[string]any to a struct
func (d *Decoder) Decode(src map[string]any, dst any) error {
	if reflect.TypeOf(dst).Kind() != reflect.Ptr {
		return fmt.Errorf("decode must recive a ptr struct")
	}
	t := reflect.TypeOf(dst).Elem()
	v := reflect.ValueOf(dst).Elem()
	for idx := 0; idx < v.NumField(); idx++ {
		field := t.Field(idx)
		if field.Anonymous {
			if err := d.decodeStruct(field.Name, src, v.Field(idx)); err != nil {
				return err
			}
			continue
		}

		tag := field.Tag.Get(d.option.TagName)
		key, omitKey, found := strings.Cut(tag, ",")
		omitempty := found && omitKey == "omitempty"

		value, ok := src[key]
		if !ok {
			if d.option.KeyReplacer != nil {
				key = d.option.KeyReplacer.Replace(key)
			}

			for _strKey := range src {
				strKey := _strKey
				if d.option.KeyReplacer != nil {
					strKey = d.option.KeyReplacer.Replace(strKey)
				}
				if strings.EqualFold(key, strKey) {
					value = src[_strKey]
					ok = true
					break
				}
			}
		}
		if !ok || value == nil {
			if omitempty {
				continue
			}
			return fmt.Errorf("key '%s' missing", key)
		}

		err := d.decode(key, value, v.Field(idx))
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *Decoder) decode(name string, data any, val reflect.Value) error {
	for {
		kind := val.Kind()
		if kind == reflect.Pointer && val.IsNil() {
			val.Set(reflect.New(val.Type().Elem()))
		}
		if ok, err := d.decodeTextUnmarshaller(name, data, val); ok {
			return err
		}
		switch {
		case isInt(kind):
			return d.decodeInt(name, data, val)
		case isUint(kind):
			return d.decodeUint(name, data, val)
		case isFloat(kind):
			return d.decodeFloat(name, data, val)
		}
		switch kind {
		case reflect.Pointer:
			val = val.Elem()
			continue
		case reflect.String:
			return d.decodeString(name, data, val)
		case reflect.Bool:
			return d.decodeBool(name, data, val)
		case reflect.Slice:
			return d.decodeSlice(name, data, val)
		case reflect.Map:
			return d.decodeMap(name, data, val)
		case reflect.Interface:
			return d.setInterface(name, data, val)
		case reflect.Struct:
			return d.decodeStruct(name, data, val)
		default:
			return fmt.Errorf("type %s not support", val.Kind().String())
		}
	}
}

func isInt(kind reflect.Kind) bool {
	switch kind {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return true
	default:
		return false
	}
}

func isUint(kind reflect.Kind) bool {
	switch kind {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	default:
		return false
	}
}

func isFloat(kind reflect.Kind) bool {
	switch kind {
	case reflect.Float32, reflect.Float64:
		return true
	default:
		return false
	}
}

func (d *Decoder) decodeInt(name string, data any, val reflect.Value) (err error) {
	dataVal := reflect.ValueOf(data)
	kind := dataVal.Kind()
	switch {
	case isInt(kind):
		val.SetInt(dataVal.Int())
	case isUint(kind) && d.option.WeaklyTypedInput:
		val.SetInt(int64(dataVal.Uint()))
	case isFloat(kind) && d.option.WeaklyTypedInput:
		val.SetInt(int64(dataVal.Float()))
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

func (d *Decoder) decodeUint(name string, data any, val reflect.Value) (err error) {
	dataVal := reflect.ValueOf(data)
	kind := dataVal.Kind()
	switch {
	case isUint(kind):
		val.SetUint(dataVal.Uint())
	case isInt(kind) && d.option.WeaklyTypedInput:
		val.SetUint(uint64(dataVal.Int()))
	case isFloat(kind) && d.option.WeaklyTypedInput:
		val.SetUint(uint64(dataVal.Float()))
	case kind == reflect.String && d.option.WeaklyTypedInput:
		var i uint64
		i, err = strconv.ParseUint(dataVal.String(), 0, val.Type().Bits())
		if err == nil {
			val.SetUint(i)
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

func (d *Decoder) decodeFloat(name string, data any, val reflect.Value) (err error) {
	dataVal := reflect.ValueOf(data)
	kind := dataVal.Kind()
	switch {
	case isFloat(kind):
		val.SetFloat(dataVal.Float())
	case isUint(kind):
		val.SetFloat(float64(dataVal.Uint()))
	case isInt(kind) && d.option.WeaklyTypedInput:
		val.SetFloat(float64(dataVal.Int()))
	case kind == reflect.String && d.option.WeaklyTypedInput:
		var i float64
		i, err = strconv.ParseFloat(dataVal.String(), val.Type().Bits())
		if err == nil {
			val.SetFloat(i)
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

func (d *Decoder) decodeString(name string, data any, val reflect.Value) (err error) {
	dataVal := reflect.ValueOf(data)
	kind := dataVal.Kind()
	switch {
	case kind == reflect.String:
		val.SetString(dataVal.String())
	case isInt(kind) && d.option.WeaklyTypedInput:
		val.SetString(strconv.FormatInt(dataVal.Int(), 10))
	case isUint(kind) && d.option.WeaklyTypedInput:
		val.SetString(strconv.FormatUint(dataVal.Uint(), 10))
	case isFloat(kind) && d.option.WeaklyTypedInput:
		val.SetString(strconv.FormatFloat(dataVal.Float(), 'E', -1, dataVal.Type().Bits()))
	default:
		err = fmt.Errorf(
			"'%s' expected type '%s', got unconvertible type '%s'",
			name, val.Type(), dataVal.Type(),
		)
	}
	return err
}

func (d *Decoder) decodeBool(name string, data any, val reflect.Value) (err error) {
	dataVal := reflect.ValueOf(data)
	kind := dataVal.Kind()
	switch {
	case kind == reflect.Bool:
		val.SetBool(dataVal.Bool())
	case isInt(kind) && d.option.WeaklyTypedInput:
		val.SetBool(dataVal.Int() != 0)
	case isUint(kind) && d.option.WeaklyTypedInput:
		val.SetString(strconv.FormatUint(dataVal.Uint(), 10))
	default:
		err = fmt.Errorf(
			"'%s' expected type '%s', got unconvertible type '%s'",
			name, val.Type(), dataVal.Type(),
		)
	}
	return err
}

func (d *Decoder) decodeSlice(name string, data any, val reflect.Value) error {
	dataVal := reflect.Indirect(reflect.ValueOf(data))
	valType := val.Type()
	valElemType := valType.Elem()

	if dataVal.Kind() == reflect.String && valElemType.Kind() == reflect.Uint8 { // from encoding/json
		s := []byte(dataVal.String())
		b := make([]byte, base64.StdEncoding.DecodedLen(len(s)))
		n, err := base64.StdEncoding.Decode(b, s)
		if err != nil {
			return fmt.Errorf("try decode '%s' by base64 error: %w", name, err)
		}
		val.SetBytes(b[:n])
		return nil
	}

	if dataVal.Kind() != reflect.Slice {
		return fmt.Errorf("'%s' is not a slice", name)
	}

	valSlice := val
	// make a new slice with cap(val)==cap(dataVal)
	// the caller can determine whether the original configuration contains this item by judging whether the value is nil.
	valSlice = reflect.MakeSlice(valType, 0, dataVal.Len())
	for i := 0; i < dataVal.Len(); i++ {
		currentData := dataVal.Index(i).Interface()
		for valSlice.Len() <= i {
			valSlice = reflect.Append(valSlice, reflect.Zero(valElemType))
		}
		fieldName := fmt.Sprintf("%s[%d]", name, i)
		if currentData == nil {
			// in weakly type mode, null will convert to zero value
			if d.option.WeaklyTypedInput {
				continue
			}
			// in non-weakly type mode, null will convert to nil if element's zero value is nil, otherwise return an error
			if elemKind := valElemType.Kind(); elemKind == reflect.Map || elemKind == reflect.Slice {
				continue
			}
			return fmt.Errorf("'%s' can not be null", fieldName)
		}
		currentField := valSlice.Index(i)
		if err := d.decode(fieldName, currentData, currentField); err != nil {
			return err
		}
	}

	val.Set(valSlice)
	return nil
}

func (d *Decoder) decodeMap(name string, data any, val reflect.Value) error {
	valType := val.Type()
	valKeyType := valType.Key()
	valElemType := valType.Elem()

	valMap := val

	if valMap.IsNil() {
		mapType := reflect.MapOf(valKeyType, valElemType)
		valMap = reflect.MakeMap(mapType)
	}

	dataVal := reflect.Indirect(reflect.ValueOf(data))
	if dataVal.Kind() != reflect.Map {
		return fmt.Errorf("'%s' expected a map, got '%s'", name, dataVal.Kind())
	}

	return d.decodeMapFromMap(name, dataVal, val, valMap)
}

func (d *Decoder) decodeMapFromMap(name string, dataVal reflect.Value, val reflect.Value, valMap reflect.Value) error {
	valType := val.Type()
	valKeyType := valType.Key()
	valElemType := valType.Elem()

	errors := make([]string, 0)

	if dataVal.Len() == 0 {
		if dataVal.IsNil() {
			if !val.IsNil() {
				val.Set(dataVal)
			}
		} else {
			val.Set(valMap)
		}

		return nil
	}

	for _, k := range dataVal.MapKeys() {
		fieldName := fmt.Sprintf("%s[%s]", name, k)

		currentKey := reflect.Indirect(reflect.New(valKeyType))
		if err := d.decode(fieldName, k.Interface(), currentKey); err != nil {
			errors = append(errors, err.Error())
			continue
		}

		v := dataVal.MapIndex(k).Interface()
		if v == nil {
			errors = append(errors, fmt.Sprintf("filed %s invalid", fieldName))
			continue
		}

		currentVal := reflect.Indirect(reflect.New(valElemType))
		if err := d.decode(fieldName, v, currentVal); err != nil {
			errors = append(errors, err.Error())
			continue
		}

		valMap.SetMapIndex(currentKey, currentVal)
	}

	val.Set(valMap)

	if len(errors) > 0 {
		return fmt.Errorf(strings.Join(errors, ","))
	}

	return nil
}

func (d *Decoder) decodeStruct(name string, data any, val reflect.Value) error {
	dataVal := reflect.Indirect(reflect.ValueOf(data))

	// If the type of the value to write to and the data match directly,
	// then we just set it directly instead of recursing into the structure.
	if dataVal.Type() == val.Type() {
		val.Set(dataVal)
		return nil
	}

	dataValKind := dataVal.Kind()
	switch dataValKind {
	case reflect.Map:
		return d.decodeStructFromMap(name, dataVal, val)
	default:
		return fmt.Errorf("'%s' expected a map, got '%s'", name, dataVal.Kind())
	}
}

func (d *Decoder) decodeStructFromMap(name string, dataVal, val reflect.Value) error {
	dataValType := dataVal.Type()
	if kind := dataValType.Key().Kind(); kind != reflect.String && kind != reflect.Interface {
		return fmt.Errorf(
			"'%s' needs a map with string keys, has '%s' keys",
			name, dataValType.Key().Kind())
	}

	dataValKeys := make(map[reflect.Value]struct{})
	dataValKeysUnused := make(map[any]struct{})
	for _, dataValKey := range dataVal.MapKeys() {
		dataValKeys[dataValKey] = struct{}{}
		dataValKeysUnused[dataValKey.Interface()] = struct{}{}
	}

	errors := make([]string, 0)

	// This slice will keep track of all the structs we'll be decoding.
	// There can be more than one struct if there are embedded structs
	// that are squashed.
	structs := make([]reflect.Value, 1, 5)
	structs[0] = val

	// Compile the list of all the fields that we're going to be decoding
	// from all the structs.
	type field struct {
		field reflect.StructField
		val   reflect.Value
	}
	var fields []field
	for len(structs) > 0 {
		structVal := structs[0]
		structs = structs[1:]

		structType := structVal.Type()

		for i := 0; i < structType.NumField(); i++ {
			fieldType := structType.Field(i)
			fieldKind := fieldType.Type.Kind()

			// If "squash" is specified in the tag, we squash the field down.
			squash := false
			tagParts := strings.Split(fieldType.Tag.Get(d.option.TagName), ",")
			for _, tag := range tagParts[1:] {
				if tag == "squash" {
					squash = true
					break
				}
			}

			if squash {
				if fieldKind != reflect.Struct {
					errors = append(errors,
						fmt.Errorf("%s: unsupported type for squash: %s", fieldType.Name, fieldKind).Error())
				} else {
					structs = append(structs, structVal.FieldByName(fieldType.Name))
				}
				continue
			}

			// Normal struct field, store it away
			fields = append(fields, field{fieldType, structVal.Field(i)})
		}
	}

	// for fieldType, field := range fields {
	for _, f := range fields {
		field, fieldValue := f.field, f.val
		fieldName := field.Name

		tagValue := field.Tag.Get(d.option.TagName)
		tagValue = strings.SplitN(tagValue, ",", 2)[0]
		if tagValue != "" {
			fieldName = tagValue
		}

		rawMapKey := reflect.ValueOf(fieldName)
		rawMapVal := dataVal.MapIndex(rawMapKey)
		if !rawMapVal.IsValid() {
			// Do a slower search by iterating over each key and
			// doing case-insensitive search.
			if d.option.KeyReplacer != nil {
				fieldName = d.option.KeyReplacer.Replace(fieldName)
			}
			for dataValKey := range dataValKeys {
				mK, ok := dataValKey.Interface().(string)
				if !ok {
					// Not a string key
					continue
				}
				if d.option.KeyReplacer != nil {
					mK = d.option.KeyReplacer.Replace(mK)
				}

				if strings.EqualFold(mK, fieldName) {
					rawMapKey = dataValKey
					rawMapVal = dataVal.MapIndex(dataValKey)
					break
				}
			}

			if !rawMapVal.IsValid() {
				// There was no matching key in the map for the value in
				// the struct. Just ignore.
				continue
			}
		}

		// Delete the key we're using from the unused map so we stop tracking
		delete(dataValKeysUnused, rawMapKey.Interface())

		if !fieldValue.IsValid() {
			// This should never happen
			panic("field is not valid")
		}

		// If we can't set the field, then it is unexported or something,
		// and we just continue onwards.
		if !fieldValue.CanSet() {
			continue
		}

		// If the name is empty string, then we're at the root, and we
		// don't dot-join the fields.
		if name != "" {
			fieldName = fmt.Sprintf("%s.%s", name, fieldName)
		}

		if err := d.decode(fieldName, rawMapVal.Interface(), fieldValue); err != nil {
			errors = append(errors, err.Error())
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf(strings.Join(errors, ","))
	}

	return nil
}

func (d *Decoder) setInterface(name string, data any, val reflect.Value) (err error) {
	dataVal := reflect.ValueOf(data)
	val.Set(dataVal)
	return nil
}

func (d *Decoder) decodeTextUnmarshaller(name string, data any, val reflect.Value) (bool, error) {
	if !val.CanAddr() {
		return false, nil
	}
	valAddr := val.Addr()
	if !valAddr.CanInterface() {
		return false, nil
	}
	unmarshaller, ok := valAddr.Interface().(encoding.TextUnmarshaler)
	if !ok {
		return false, nil
	}
	var str string
	if err := d.decodeString(name, data, reflect.Indirect(reflect.ValueOf(&str))); err != nil {
		return false, err
	}
	if err := unmarshaller.UnmarshalText([]byte(str)); err != nil {
		return true, fmt.Errorf("cannot parse '%s' as %s: %s", name, val.Type(), err)
	}
	return true, nil
}
