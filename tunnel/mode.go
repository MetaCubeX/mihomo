package tunnel

import (
	"encoding/json"
	"errors"
)

type Mode int

var (
	// ModeMapping is a mapping for Mode enum
	ModeMapping = map[string]Mode{
		"Global": Global,
		"Rule":   Rule,
		"Direct": Direct,
	}
)

const (
	Global Mode = iota
	Rule
	Direct
)

// UnmarshalJSON unserialize Mode
func (m *Mode) UnmarshalJSON(data []byte) error {
	var tp string
	json.Unmarshal(data, tp)
	mode, exist := ModeMapping[tp]
	if !exist {
		return errors.New("invalid mode")
	}
	*m = mode
	return nil
}

// MarshalJSON serialize Mode
func (m Mode) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.String())
}

func (m Mode) String() string {
	switch m {
	case Global:
		return "Global"
	case Rule:
		return "Rule"
	case Direct:
		return "Direct"
	default:
		return "Unknow"
	}
}
