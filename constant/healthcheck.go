package constant

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/dlclark/regexp2"

	"github.com/metacubex/mihomo/common/utils"
)

const (
	HealthCheckMethodHead = "http_head"
	HealthCheckMethodGet  = "http_get"
)

type HealthCheckOption struct {
	ExpectedStatus    utils.IntRanges[uint16]
	Method            string
	Headers           map[string][]string
	ExpectedBodyMatch string
}

func NewHealthCheckOption(expectedStatus utils.IntRanges[uint16], method string, rawHeaders any, expectedBodyMatch string) (HealthCheckOption, error) {
	method, err := NormalizeHealthCheckMethod(method)
	if err != nil {
		return HealthCheckOption{}, err
	}
	if expectedBodyMatch != "" && method != HealthCheckMethodGet {
		return HealthCheckOption{}, fmt.Errorf("expected-body-match requires check-method %s", HealthCheckMethodGet)
	}
	if expectedBodyMatch != "" {
		if _, err := regexp2.Compile(expectedBodyMatch, regexp2.None); err != nil {
			return HealthCheckOption{}, fmt.Errorf("expected-body-match regex error: %w", err)
		}
	}

	headers, err := ParseHealthCheckHeaders(rawHeaders)
	if err != nil {
		return HealthCheckOption{}, err
	}

	return HealthCheckOption{
		ExpectedStatus:    expectedStatus,
		Method:            method,
		Headers:           headers,
		ExpectedBodyMatch: expectedBodyMatch,
	}, nil
}

func (o HealthCheckOption) WithDefault() HealthCheckOption {
	if o.Method == "" {
		o.Method = HealthCheckMethodHead
	}
	return o
}

func NormalizeHealthCheckMethod(method string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "", HealthCheckMethodHead, "head", "http-head":
		return HealthCheckMethodHead, nil
	case HealthCheckMethodGet, "get", "http-get":
		return HealthCheckMethodGet, nil
	default:
		return "", fmt.Errorf("unsupported health check method: %s", method)
	}
}

func ParseHealthCheckHeaders(raw any) (map[string][]string, error) {
	if raw == nil {
		return nil, nil
	}

	headers := map[string][]string{}
	if err := appendHealthCheckHeaders(headers, raw); err != nil {
		return nil, err
	}
	if len(headers) == 0 {
		return nil, nil
	}
	return headers, nil
}

func appendHealthCheckHeaders(headers map[string][]string, raw any) error {
	if raw == nil {
		return nil
	}

	rv := reflect.ValueOf(raw)
	if !rv.IsValid() {
		return nil
	}

	switch rv.Kind() {
	case reflect.Map:
		return appendHealthCheckHeadersFromMap(headers, rv)
	case reflect.Slice, reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			if err := appendHealthCheckHeaderItem(headers, rv.Index(i).Interface()); err != nil {
				return fmt.Errorf("http-headers[%d]: %w", i, err)
			}
		}
		return nil
	default:
		return fmt.Errorf("http-headers expected map or array, got %T", raw)
	}
}

func appendHealthCheckHeaderItem(headers map[string][]string, raw any) error {
	switch item := raw.(type) {
	case string:
		name, value, ok := strings.Cut(item, ":")
		if !ok {
			return fmt.Errorf("header string must be in 'Name: value' format")
		}
		appendHealthCheckHeaderValue(headers, name, value)
		return nil
	default:
		rv := reflect.ValueOf(raw)
		if rv.IsValid() && rv.Kind() == reflect.Map {
			return appendHealthCheckHeadersFromMap(headers, rv)
		}
		return fmt.Errorf("unsupported header item %T", raw)
	}
}

func appendHealthCheckHeadersFromMap(headers map[string][]string, data reflect.Value) error {
	if data.Len() == 0 {
		return nil
	}

	nameValue, hasName := mapStringLookup(data, "name")
	if hasName {
		name, ok := asString(nameValue.Interface())
		if !ok {
			return fmt.Errorf("header name must be string")
		}

		if value, ok := mapStringLookup(data, "value"); ok {
			return appendHealthCheckHeaderValues(headers, name, value.Interface())
		}
		if value, ok := mapStringLookup(data, "values"); ok {
			return appendHealthCheckHeaderValues(headers, name, value.Interface())
		}
		return fmt.Errorf("header with name must contain value or values")
	}

	for _, key := range data.MapKeys() {
		name, ok := asString(key.Interface())
		if !ok {
			return fmt.Errorf("header name must be string")
		}
		if err := appendHealthCheckHeaderValues(headers, name, data.MapIndex(key).Interface()); err != nil {
			return err
		}
	}
	return nil
}

func appendHealthCheckHeaderValues(headers map[string][]string, name string, raw any) error {
	switch value := raw.(type) {
	case string:
		appendHealthCheckHeaderValue(headers, name, value)
		return nil
	}

	rv := reflect.ValueOf(raw)
	if !rv.IsValid() {
		return nil
	}

	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			value, ok := asString(rv.Index(i).Interface())
			if !ok {
				return fmt.Errorf("header %s value must be string", name)
			}
			appendHealthCheckHeaderValue(headers, name, value)
		}
		return nil
	default:
		value, ok := asString(raw)
		if !ok {
			return fmt.Errorf("header %s value must be string", name)
		}
		appendHealthCheckHeaderValue(headers, name, value)
		return nil
	}
}

func appendHealthCheckHeaderValue(headers map[string][]string, name string, value string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	headers[name] = append(headers[name], strings.TrimSpace(value))
}

func mapStringLookup(data reflect.Value, key string) (reflect.Value, bool) {
	for _, mapKey := range data.MapKeys() {
		if name, ok := asString(mapKey.Interface()); ok && strings.EqualFold(name, key) {
			return data.MapIndex(mapKey), true
		}
	}
	return reflect.Value{}, false
}

func asString(raw any) (string, bool) {
	if raw == nil {
		return "", false
	}
	value, ok := raw.(string)
	return value, ok
}
