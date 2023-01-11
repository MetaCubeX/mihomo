package process

import (
	"encoding/json"
	"errors"
	"strings"
)

const (
	FindProcessAlways = "always"
	FindProcessStrict = "strict"
	FindProcessOff    = "off"
)

var (
	validModes = map[string]struct{}{
		FindProcessAlways: {},
		FindProcessOff:    {},
		FindProcessStrict: {},
	}
)

type FindProcessMode string

func (m FindProcessMode) Always() bool {
	return m == FindProcessAlways
}

func (m FindProcessMode) Off() bool {
	return m == FindProcessOff
}

func (m *FindProcessMode) UnmarshalYAML(unmarshal func(any) error) error {
	var tp string
	if err := unmarshal(&tp); err != nil {
		return err
	}
	return m.Set(tp)
}

func (m *FindProcessMode) UnmarshalJSON(data []byte) error {
	var tp string
	if err := json.Unmarshal(data, &tp); err != nil {
		return err
	}
	return m.Set(tp)
}

func (m *FindProcessMode) Set(value string) error {
	mode := strings.ToLower(value)
	_, exist := validModes[mode]
	if !exist {
		return errors.New("invalid find process mode")
	}
	*m = FindProcessMode(mode)
	return nil
}
