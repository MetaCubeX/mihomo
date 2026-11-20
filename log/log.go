package log

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/metacubex/mihomo/common/observable"

	log "github.com/sirupsen/logrus"
)

var (
	logCh            = make(chan Event)
	source           = observable.NewObservable[Event](logCh)
	level            atomic.Int32
	debugEnabled     atomic.Bool
	interestMu       sync.Mutex
	debugSubscribers = make(map[observable.Subscription[Event]]struct{})
)

func init() {
	level.Store(int32(INFO))
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:             true,
		TimestampFormat:           "2006-01-02T15:04:05.000000000Z07:00",
		EnvironmentOverrideColors: true,
	})
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

// DebugEnabled reports whether the terminal or a subscriber needs DEBUG events.
func DebugEnabled() bool {
	return debugEnabled.Load()
}

func Debugln(format string, v ...any) {
	if !DebugEnabled() {
		return
	}
	event := newLog(DEBUG, format, v...)
	logCh <- event
	print(event)
}

func Fatalln(format string, v ...any) {
	log.Fatalf(format, v...)
}

// Subscribe retains the unfiltered subscription's DEBUG interest.
func Subscribe() observable.Subscription[Event] {
	return SubscribeLevel(DEBUG)
}

// SubscribeLevel declares the lowest level a consumer needs. Events remain
// multicast; consumers must still filter events below their requested level.
func SubscribeLevel(minLevel LogLevel) observable.Subscription[Event] {
	sub, err := source.Subscribe()
	if err == nil && minLevel <= DEBUG {
		interestMu.Lock()
		debugSubscribers[sub] = struct{}{}
		updateDebugEnabled()
		interestMu.Unlock()
	}
	return sub
}

func UnSubscribe(sub observable.Subscription[Event]) {
	interestMu.Lock()
	delete(debugSubscribers, sub)
	updateDebugEnabled()
	interestMu.Unlock()
	// Observable operations can wait for slow consumers. Do not hold the
	// interest writer lock while waiting, which would also block SetLevel.
	source.UnSubscribe(sub)
}

func Level() LogLevel {
	return LogLevel(level.Load())
}

func SetLevel(newLevel LogLevel) {
	interestMu.Lock()
	defer interestMu.Unlock()
	level.Store(int32(newLevel))
	updateDebugEnabled()
}

// Called under interestMu so a terminal/subscriber handoff cannot publish a
// transient false value while DEBUG is continuously needed.
func updateDebugEnabled() {
	debugEnabled.Store(Level() <= DEBUG || len(debugSubscribers) != 0)
}

func print(data Event) {
	if data.LogLevel < Level() {
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
