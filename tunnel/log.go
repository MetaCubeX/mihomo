package tunnel

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

const (
	INFO LogType = iota
	WARNING
	ERROR
	DEBUG
)

type LogType int

type Log struct {
	LogType LogType
	Payload string
}

func (l *Log) Type() string {
	switch l.LogType {
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
	switch data.LogType {
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

func newLog(logType LogType, format string, v ...interface{}) Log {
	return Log{
		LogType: logType,
		Payload: fmt.Sprintf(format, v...),
	}
}
