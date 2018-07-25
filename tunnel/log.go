package tunnel

import (
	"fmt"

	C "github.com/Dreamacro/clash/constant"

	log "github.com/sirupsen/logrus"
)

type Log struct {
	LogLevel C.LogLevel
	Payload  string
}

func (l *Log) Type() string {
	return l.LogLevel.String()
}

func print(data Log) {
	switch data.LogLevel {
	case C.INFO:
		log.Infoln(data.Payload)
	case C.WARNING:
		log.Warnln(data.Payload)
	case C.ERROR:
		log.Errorln(data.Payload)
	case C.DEBUG:
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
		if data.LogLevel <= t.logLevel {
			print(data)
		}
	}
}

func newLog(logLevel C.LogLevel, format string, v ...interface{}) Log {
	return Log{
		LogLevel: logLevel,
		Payload:  fmt.Sprintf(format, v...),
	}
}
