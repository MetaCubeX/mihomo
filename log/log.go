package log

import (
	"bytes"
	"fmt"
	"gopkg.in/natefinch/lumberjack.v2"
	"os"

	"github.com/metacubex/mihomo/common/observable"

	log "github.com/sirupsen/logrus"
)

var (
	logCh  = make(chan Event)
	source = observable.NewObservable[Event](logCh)
	level  = INFO
)

type MylogFormatter struct {
}

func (f *MylogFormatter) Format(entry *log.Entry) ([]byte, error) {

	var b *bytes.Buffer
	if entry.Buffer != nil {
		b = entry.Buffer
	} else {
		b = &bytes.Buffer{}
	}

	b.WriteString(entry.Time.Format("2006/01/02 15:04:05"))
	b.WriteString(fmt.Sprintf(" |%.4s| ", entry.Level))

	b.WriteString(entry.Message)

	b.WriteByte('\n')
	return b.Bytes(), nil
}
func init() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	//log.SetFormatter(&log.TextFormatter{
	//	FullTimestamp:             true,
	//	TimestampFormat:           "2006/01/02 15:04:05",
	//	EnvironmentOverrideColors: true,
	//})
	log.SetFormatter(&MylogFormatter{})
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

func SetOutput(file string, maxSize, maxBackups, maxAge int, compress bool) {
	if file != "" {
		log.SetOutput(&lumberjack.Logger{
			Filename:   file,
			MaxSize:    maxSize, // megabytes
			MaxBackups: maxBackups,
			MaxAge:     maxAge,   //days
			Compress:   compress, // disabled by default
		})
	}
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
