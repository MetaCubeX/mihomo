package tunnel

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

const (
	ERROR LogLevel = iota
	WARNING
	INFO
	DEBUG
)

type LogLevel int

type Log struct {
	LogLevel LogLevel
	Payload  string
}

func (l *Log) Type() string {
	switch l.LogLevel {
	case INFO:
		return "Info"
	case WARNING:
		return "Warning"
	case ERROR:
		return "Error"
	case DEBUG:
		return "Debug"
	default:
		return "Unknow"
	}
}

func print(data Log) {
	switch data.LogLevel {
	case INFO:
		log.Infoln(data.Payload)
	case WARNING:
		log.Warnln(data.Payload)
	case ERROR:
		log.Errorln(data.Payload)
	case DEBUG:
		log.Debugln(data.Payload)
	}
}

func (t *Tunnel) subscribeLogs() {
	sub, err := t.observable.Subscribe()
	if err != nil {
		log.Fatalf("Can't subscribe tunnel log: %s", err.Error())
	}
	for elm := range sub {
		data := elm.(Log)
		print(data)
	}
}

func newLog(logLevel LogLevel, format string, v ...interface{}) Log {
	return Log{
		LogLevel: logLevel,
		Payload:  fmt.Sprintf(format, v...),
	}
}
