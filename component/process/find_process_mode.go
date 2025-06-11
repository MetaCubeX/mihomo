package process

import (
	"errors"
	"strings"
)

const (
	FindProcessStrict FindProcessMode = iota
	FindProcessAlways
	FindProcessOff
)

var (
	validModes = map[string]FindProcessMode{
		FindProcessStrict.String(): FindProcessStrict,
		FindProcessAlways.String(): FindProcessAlways,
		FindProcessOff.String():    FindProcessOff,
	}
)

type FindProcessMode int32

// UnmarshalText unserialize FindProcessMode
func (m *FindProcessMode) UnmarshalText(data []byte) error {
	return m.Set(string(data))
}

func (m *FindProcessMode) Set(value string) error {
	mode, exist := validModes[strings.ToLower(value)]
	if !exist {
		return errors.New("invalid find process mode")
	}
	*m = mode
	return nil
}

// MarshalText serialize FindProcessMode
func (m FindProcessMode) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

func (m FindProcessMode) String() string {
	switch m {
	case FindProcessAlways:
		return "always"
	case FindProcessOff:
		return "off"
	default:
		return "strict"
	}
}
