package log

import (
	"fmt"

	"github.com/metacubex/mihomo/common/observable"

	log "github.com/sirupsen/logrus"
)

type LogFormatter string

const (
	LogFormatterCustomText LogFormatter = "custom-text"
	LogFormatterText       LogFormatter = "text"
	LogFormatterJSON       LogFormatter = "json"
)

type LogConfig struct {
	Level           LogLevel
	Formatter       LogFormatter
	TimestampFormat string
}

type CustomTextFormatter struct {
	FullTimestamp   bool
	TimestampFormat string
}

func (f *CustomTextFormatter) Format(entry *log.Entry) ([]byte, error) {
	var b []byte
	if f.FullTimestamp {
		b = append(b, "time="...)
		b = append(b, entry.Time.Format(f.TimestampFormat)...)
		b = append(b, ' ')
	}
	b = append(b, "level="...)
	b = append(b, entry.Level.String()...)
	b = append(b, ' ')
	b = append(b, "msg="...)
	b = append(b, entry.Message...)
	b = append(b, '\n')
	return b, nil
}

var (
	logCh  = make(chan Event)
	source = observable.NewObservable[Event](logCh)
	level  = INFO
)

func init() {
	SetFormatter(LogConfig{
		Level:           INFO,
		Formatter:       LogFormatterCustomText,
		TimestampFormat: "2006-01-02T15:04:05.000000000Z07:00",
	})
}

func SetFormatter(cfg LogConfig) {
	level = cfg.Level
	log.SetLevel(toLogrusLevel(cfg.Level))

	switch cfg.Formatter {
	case LogFormatterJSON:
		log.SetFormatter(&log.JSONFormatter{
			TimestampFormat: cfg.TimestampFormat,
		})
	case LogFormatterText:
		log.SetFormatter(&log.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: cfg.TimestampFormat,
			DisableColors:   true,
		})
	default:
		log.SetFormatter(&CustomTextFormatter{
			FullTimestamp:   true,
			TimestampFormat: cfg.TimestampFormat,
		})
	}
}

func toLogrusLevel(lvl LogLevel) log.Level {
	switch lvl {
	case DEBUG:
		return log.DebugLevel
	case INFO:
		return log.InfoLevel
	case WARNING:
		return log.WarnLevel
	case ERROR:
		return log.ErrorLevel
	case SILENT:
		return log.InfoLevel
	default:
		return log.InfoLevel
	}
}

type Event struct {
	LogLevel LogLevel
	Payload  string
}

func (e *Event) Type() string {
	return e.LogLevel.String()
}

func Infoln(format string, v ...any) {
	event := newLog(INFO, format, v...)
	logCh <- event
	print(event)
}

func Warnln(format string, v ...any) {
	event := newLog(WARNING, format, v...)
	logCh <- event
	print(event)
}

func Errorln(format string, v ...any) {
	event := newLog(ERROR, format, v...)
	logCh <- event
	print(event)
}

func Debugln(format string, v ...any) {
	event := newLog(DEBUG, format, v...)
	logCh <- event
	print(event)
}

func Fatalln(format string, v ...any) {
	log.Fatalf(format, v...)
}

func Subscribe() observable.Subscription[Event] {
	sub, _ := source.Subscribe()
	return sub
}

func UnSubscribe(sub observable.Subscription[Event]) {
	source.UnSubscribe(sub)
}

func Level() LogLevel {
	return level
}

func SetLevel(newLevel LogLevel) {
	level = newLevel
}

func print(data Event) {
	if data.LogLevel < level {
		return
	}

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

func newLog(logLevel LogLevel, format string, v ...any) Event {
	return Event{
		LogLevel: logLevel,
		Payload:  fmt.Sprintf(format, v...),
	}
}
