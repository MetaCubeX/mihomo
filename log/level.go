package log

import (
	"errors"
	"strings"
)

// LogLevelMapping is a mapping for LogLevel enum
var LogLevelMapping = map[string]LogLevel{
	ERROR.String():   ERROR,
	WARNING.String(): WARNING,
	INFO.String():    INFO,
	DEBUG.String():   DEBUG,
	SILENT.String():  SILENT,
}

const (
	DEBUG LogLevel = iota
	INFO
	WARNING
	ERROR
	SILENT
)

type LogLevel int

// UnmarshalText unserialize LogLevel
func (l *LogLevel) UnmarshalText(data []byte) error {
	level, exist := LogLevelMapping[strings.ToLower(string(data))]
	if !exist {
		return errors.New("invalid log-level")
	}
	*l = level
	return nil
}

// MarshalText serialize LogLevel
func (l LogLevel) MarshalText() ([]byte, error) {
	return []byte(l.String()), nil
}

func (l LogLevel) String() string {
	switch l {
	case INFO:
		return "info"
	case WARNING:
		return "warning"
	case ERROR:
		return "error"
	case DEBUG:
		return "debug"
	case SILENT:
		return "silent"
	default:
		return "unknown"
	}
}
