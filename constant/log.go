package constant

var (
	// LogLevelMapping is a mapping for LogLevel enum
	LogLevelMapping = map[string]LogLevel{
		"error":   ERROR,
		"warning": WARNING,
		"info":    INFO,
		"debug":   DEBUG,
	}
)

const (
	ERROR LogLevel = iota
	WARNING
	INFO
	DEBUG
)

type LogLevel int

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
	default:
		return "unknow"
	}
}
