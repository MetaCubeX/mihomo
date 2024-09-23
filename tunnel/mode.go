package tunnel

import (
	"encoding/json"
	"errors"
	"strings"
)

type TunnelMode int

// ModeMapping is a mapping for Mode enum
var ModeMapping = map[string]TunnelMode{
	Global.String(): Global,
	Rule.String():   Rule,
	Direct.String(): Direct,
}

const (
	Global TunnelMode = iota
	Rule
	Direct
)

// UnmarshalYAML unserialize Mode with yaml
func (m *TunnelMode) UnmarshalYAML(unmarshal func(any) error) error {
	var tp string
	unmarshal(&tp)
	mode, exist := ModeMapping[strings.ToLower(tp)]
	if !exist {
		return errors.New("invalid mode")
	}
	*m = mode
	return nil
}

// UnmarshalJSON unserialize Mode
func (m *TunnelMode) UnmarshalJSON(data []byte) error {
	var tp string
	json.Unmarshal(data, &tp)
	mode, exist := ModeMapping[strings.ToLower(tp)]
	if !exist {
		return errors.New("invalid mode")
	}
	*m = mode
	return nil
}

// UnmarshalText unserialize Mode
func (m *TunnelMode) UnmarshalText(data []byte) error {
	mode, exist := ModeMapping[strings.ToLower(string(data))]
	if !exist {
		return errors.New("invalid mode")
	}
	*m = mode
	return nil
}

// MarshalYAML serialize TunnelMode with yaml
func (m TunnelMode) MarshalYAML() (any, error) {
	return m.String(), nil
}

// MarshalJSON serialize Mode
func (m TunnelMode) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.String())
}

// MarshalText serialize Mode
func (m TunnelMode) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

func (m TunnelMode) String() string {
	switch m {
	case Global:
		return "global"
	case Rule:
		return "rule"
	case Direct:
		return "direct"
	default:
		return "Unknown"
	}
}
