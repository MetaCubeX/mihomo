package tunnel

import (
	"errors"
	"strings"
)

type TunnelMode int32

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

// UnmarshalText unserialize Mode
func (m *TunnelMode) UnmarshalText(data []byte) error {
	mode, exist := ModeMapping[strings.ToLower(string(data))]
	if !exist {
		return errors.New("invalid mode")
	}
	*m = mode
	return nil
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
